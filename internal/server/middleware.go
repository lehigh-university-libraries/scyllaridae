package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/islandora/scyllaridae/internal/config"
	"github.com/islandora/scyllaridae/pkg/api"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type contextKey string

const cmdKey contextKey = "scyllaridaeCmd"
const msgKey contextKey = "scyllaridaeMsg"

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

func (s *Server) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		statusWriter := &statusRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		auth := ""
		if *s.Config.ForwardAuth {
			auth = r.Header.Get("Authorization")
		}

		// since building the command involves reading the request body
		// and we want to build the command here so we can add some context to our log messages
		// along with the timing information and response status
		// we're doing the setup here and adding the information in the context
		// this allows us to read streams needed to process the request only once
		message, err := api.DecodeAlpacaMessage(r, auth)
		if err != nil {
			if strings.HasPrefix(err.Error(), "payload validation failed") {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			slog.Error("Error decoding alpaca message", "err", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		cmd, err := config.BuildExecCommand(message, s.Config)
		if err != nil {
			slog.Error("Error building command", "err", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		ctx := context.WithValue(r.Context(), cmdKey, cmd)
		ctx = context.WithValue(ctx, msgKey, message)
		next.ServeHTTP(statusWriter, r.WithContext(ctx))
		duration := time.Since(start)

		slog.Info(r.Method,
			"path", r.URL.Path,
			"status", statusWriter.statusCode,
			"duration", duration,
			"client_ip", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"command", cmd.String(),
			"msgId", message.Object.ID,
		)
	})
}

// JWTAuthMiddleware validates a JWT token and adds claims to the context
func (s *Server) JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip JWT verification if no JWKS URI is configured
		skipJwtVerify := s.Config.JwksUri == ""

		a := r.Header.Get("Authorization")
		if a == "" || len(a) <= 7 || !strings.EqualFold(a[:7], "bearer ") {
			slog.Debug("No Authorization header passed")
			if !skipJwtVerify {
				http.Error(w, "Missing Authorization header", http.StatusBadRequest)
				return
			}
		}

		if !skipJwtVerify {
			slog.Debug("Verifying JWT")
			tokenString := a[7:]
			err := s.verifyJWT(tokenString)
			if err != nil {
				slog.Error("JWT verification failed", "err", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		slog.Debug("JWT verified or skipped")

		next.ServeHTTP(w, r)
	})
}

func (s *Server) verifyJWT(tokenString string) error {
	keySet, err := s.fetchJWKS()
	if err != nil {
		return fmt.Errorf("unable to fetch JWKS: %v", err)
	}

	// islandora will only ever provide a single key to sign JWTs
	// so just use the one key in JWKS
	key, ok := keySet.Key(0)
	if !ok {
		return fmt.Errorf("no key in jwks")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var token jwt.Token
	if keySet.Len() > 1 {
		token, err = jwt.Parse([]byte(tokenString),
			jwt.WithContext(ctx),
			jwt.WithKeySet(keySet),
		)
	} else {
		token, err = jwt.Parse([]byte(tokenString),
			jwt.WithContext(ctx),
			jwt.WithKey(jwa.RS256(), key),
		)
	}
	if err != nil {
		return fmt.Errorf("unable to parse token: %v", err)
	}

	err = jwt.Validate(token)
	if err != nil {
		return fmt.Errorf("unable to validate token: %v", err)
	}

	return nil
}

// fetchJWKS fetches the JSON Web Key Set (JWKS) from the given URI
func (s *Server) fetchJWKS() (jwk.Set, error) {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	jwksURI := s.Config.JwksUri

	ks, ok := s.KeySets.Get(jwksURI)
	if ok {
		return ks, nil
	}

	ks, err = jwk.Fetch(ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch jwks: %v", err)
	}

	evicted := s.KeySets.Add(jwksURI, ks)
	if evicted {
		slog.Warn("server jwks cache is too small")
	}

	return ks, nil
}
