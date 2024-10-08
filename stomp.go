package main

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	stomp "github.com/go-stomp/stomp/v3"
	scyllaridae "github.com/lehigh-university-libraries/scyllaridae/internal/config"
	"github.com/lehigh-university-libraries/scyllaridae/pkg/api"
)

func runStompSubscribers(config *scyllaridae.ServerConfig) {
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	var wg sync.WaitGroup

	for _, middleware := range config.QueueMiddlewares {
		wg.Add(1)
		go func(middleware scyllaridae.QueueMiddleware) {
			defer wg.Done()
			messageChan := make(chan *stomp.Message, middleware.Consumers)

			// Start the specified number of worker goroutines
			for i := 0; i < middleware.Consumers; i++ {
				slog.Info("Adding consumer", "consumer", i)
				go worker(messageChan, middleware)
			}

			RecvStompMessages(middleware.QueueName, messageChan)
		}(middleware)
	}

	<-stopChan
	slog.Info("Shutting down message listener")
}

func worker(messageChan <-chan *stomp.Message, middleware scyllaridae.QueueMiddleware) {
	for msg := range messageChan {
		handleMessage(msg, middleware)
	}
}

func RecvStompMessages(queueName string, messageChan chan<- *stomp.Message) {
	attempt := 0
	maxAttempts := 30
	for attempt = 0; attempt < maxAttempts; attempt++ {
		if err := connectAndSubscribe(queueName, messageChan); err != nil {
			slog.Error("Resubscribing", "queue", queueName, "error", err)
			if err := retryWithExponentialBackoff(attempt, maxAttempts); err != nil {
				slog.Error("Failed subscribing after too many failed attempts", "queue", queueName, "attempts", attempt)
				return
			}
		} else {
			// Subscription was successful
			break
		}
	}
}

func connectAndSubscribe(queueName string, messageChan chan<- *stomp.Message) error {
	addr := os.Getenv("STOMP_SERVER_ADDR")
	if addr == "" {
		addr = "activemq:61613"
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		slog.Error("Cannot connect to port", "err", err.Error())
		return err
	}
	tcpConn := c.(*net.TCPConn)

	err = tcpConn.SetKeepAlive(true)
	if err != nil {
		slog.Error("Cannot set keepalive", "err", err.Error())
		return err
	}

	err = tcpConn.SetKeepAlivePeriod(10 * time.Second)
	if err != nil {
		slog.Error("Cannot set keepalive period", "err", err.Error())
		return err
	}

	conn, err := stomp.Connect(tcpConn, stomp.ConnOpt.HeartBeat(10*time.Second, 0*time.Second))
	if err != nil {
		slog.Error("Cannot connect to STOMP server", "err", err.Error())
		return err
	}
	defer func() {
		err := conn.Disconnect()
		if err != nil {
			slog.Error("Problem disconnecting from STOMP server", "err", err)
		}
	}()

	sub, err := conn.Subscribe(queueName, stomp.AckAuto)
	if err != nil {
		slog.Error("Cannot subscribe to queue", "queue", queueName, "err", err.Error())
		return err
	}
	defer func() {
		if !sub.Active() {
			return
		}
		err := sub.Unsubscribe()
		if err != nil {
			slog.Error("Problem unsubscribing", "err", err)
		}
	}()
	slog.Info("Server subscribed to", "queue", queueName)

	for msg := range sub.C {
		if msg == nil || len(msg.Body) == 0 {
			if !sub.Active() {
				return fmt.Errorf("no longer subscribed to %s", queueName)
			}
			continue
		}
		messageChan <- msg // Send the message to the channel
	}

	return nil
}

func handleMessage(msg *stomp.Message, middleware scyllaridae.QueueMiddleware) {
	req, err := http.NewRequest("GET", middleware.Url, nil)
	if err != nil {
		slog.Error("Error creating HTTP request", "url", middleware.Url, "err", err)
		return
	}

	req.Header.Set("X-Islandora-Event", base64.StdEncoding.EncodeToString(msg.Body))
	islandoraMessage, err := api.DecodeEventMessage(msg.Body)
	if err != nil {
		slog.Error("Unable to decode event message", "err", err)
		return
	}

	if middleware.ForwardAuth {
		auth := msg.Header.Get("Authorization")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error sending HTTP GET request", "url", middleware.Url, "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 299 {
		slog.Error("Failed to deliver message", "url", middleware.Url, "status", resp.StatusCode)
		return
	}

	if middleware.NoPut {
		return
	}

	putReq, err := http.NewRequest("PUT", islandoraMessage.Attachment.Content.DestinationURI, resp.Body)
	if err != nil {
		slog.Error("Error creating HTTP PUT request", "url", islandoraMessage.Attachment.Content.DestinationURI, "err", err)
		return
	}

	putReq.Header.Set("Authorization", msg.Header.Get("Authorization"))
	putReq.Header.Set("Content-Type", islandoraMessage.Attachment.Content.DestinationMimeType)
	putReq.Header.Set("Content-Location", islandoraMessage.Attachment.Content.FileUploadURI)

	// Send the PUT request
	putResp, err := client.Do(putReq)
	if err != nil {
		slog.Error("Error sending HTTP PUT request", "url", islandoraMessage.Attachment.Content.DestinationURI, "err", err)
		return
	}
	defer putResp.Body.Close()

	if putResp.StatusCode >= 299 {
		slog.Error("Failed to PUT data", "url", islandoraMessage.Attachment.Content.DestinationURI, "status", putResp.StatusCode)
	} else {
		slog.Info("Successfully PUT data to", "url", islandoraMessage.Attachment.Content.DestinationURI, "status", putResp.StatusCode)
	}
}

func retryWithExponentialBackoff(attempt int, maxAttempts int) error {
	if attempt >= maxAttempts {
		return fmt.Errorf("maximum retry attempts reached")
	}
	wait := time.Duration(rand.Intn(1<<attempt)) * time.Second
	time.Sleep(wait)
	return nil
}
