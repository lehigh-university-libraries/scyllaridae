package config

import (
	"fmt"
	"log/slog"
	"mime"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// ServerConfig defines server-specific configurations.
//
// swagger:model ServerConfig
type ServerConfig struct {
	// Label of the server configuration used for identification.
	//
	// required: true
	Label string `yaml:"label"`

	// HTTP method used for sending data to the destination server.
	//
	// required: false
	DestinationHTTPMethod string `yaml:"destinationHttpMethod"`

	// Header name for the file resource.
	//
	// required: false
	FileHeader string `yaml:"fileHeader,omitempty"`

	// Header name for additional arguments passed to the command.
	//
	// required: false
	ArgHeader string `yaml:"argHeader,omitempty"`

	// Indicates whether the authentication header should be forwarded.
	//
	// required: false
	ForwardAuth bool `yaml:"forwardAuth,omitempty"`

	// List of MIME types allowed for processing.
	//
	// required: true
	AllowedMimeTypes []string `yaml:"allowedMimeTypes"`

	// Commands and arguments ran by MIME type.
	//
	// required: true
	CmdByMimeType map[string]Command `yaml:"cmdByMimeType"`
}

// Command describes the command and arguments to execute for a specific MIME type.
//
// swagger:model Command
type Command struct {
	// Command to execute.
	//
	// required: true
	Cmd string `yaml:"cmd"`

	// Arguments for the command.
	//
	// required: false
	Args []string `yaml:"args"`
}

func IsAllowedMimeType(mimetype string, allowedFormats []string) bool {
	for _, format := range allowedFormats {
		if format == mimetype {
			return true
		}
		// if the config specified any mimetype is allowed
		if format == "*" {
			return true
		}
		if strings.HasSuffix(format, "/*") {
			// Check wildcard MIME type
			prefix := strings.TrimSuffix(format, "*")
			if strings.HasPrefix(mimetype, prefix) {
				return true
			}
		}
	}
	return false
}

func ReadConfig(yp string) (*ServerConfig, error) {
	var (
		y   []byte
		err error
	)
	yml := os.Getenv("SCYLLARIDAE_YML")
	if yml != "" {
		y = []byte(yml)
	} else {
		y, err = os.ReadFile(yp)
		if err != nil {
			return nil, err
		}
	}

	var c ServerConfig
	err = yaml.Unmarshal(y, &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func BuildExecCommand(sourceMimeType, destinationMimeType, addtlArgs string, c *ServerConfig) (*exec.Cmd, error) {
	if !IsAllowedMimeType(sourceMimeType, c.AllowedMimeTypes) {
		return nil, fmt.Errorf("undefined sourceMimeType: %s", sourceMimeType)
	}

	cmdConfig, exists := c.CmdByMimeType[sourceMimeType]
	if !exists {
		cmdConfig = c.CmdByMimeType["default"]
	}

	args := []string{}
	for _, a := range cmdConfig.Args {
		// if we have the special value of %args
		// replace it with the args passed by the event
		if a == "%args" && addtlArgs != "" {
			args = append(args, addtlArgs)

			// if we have the special value of %source-mime-ext
			// replace it with the source mimetype extension
		} else if a == "%source-mime-ext" {
			extensions, err := mime.ExtensionsByType(sourceMimeType)
			if err != nil || len(extensions) == 0 {
				slog.Error("unknown mime extension", "mimetype", sourceMimeType, "err", err)
				return nil, fmt.Errorf("unknown mime extension: %s", sourceMimeType)
			}
			args = append(args, strings.TrimPrefix(extensions[0], "."))

			// if we have the special value of %destination-mime-ext
			// replace it with the source mimetype extension
		} else if a == "%destination-mime-ext" {
			extensions, err := mime.ExtensionsByType(destinationMimeType)
			if err != nil || len(extensions) == 0 {
				slog.Error("unknown mime extension", "mimetype", destinationMimeType, "err", err)
				return nil, fmt.Errorf("unknown mime extension: %s", destinationMimeType)
			}
			args = append(args, strings.TrimPrefix(extensions[0], "."))

		} else {
			args = append(args, a)
		}
	}

	cmd := exec.Command(cmdConfig.Cmd, args...)

	return cmd, nil
}
