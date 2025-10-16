package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
)

// Payload defines the structure of the JSON payload received by the server.
//
// swagger:model Payload
type Payload struct {
	Actor         Actor      `json:"actor" description:"Details of the actor performing the action"`
	Object        Object     `json:"object" description:"Contains details about the object of the action"`
	Attachment    Attachment `json:"attachment" description:"Holds additional data related to the action"`
	Target        string     `json:"target" description:"Target for the payload" validate:"uri"`
	Type          string     `json:"type" description:"Type of the payload"`
	Summary       string     `json:"summary" description:"Summary of the payload"`
	Authorization string     `json:"authorization" description:"The Authorization HTTP header" validate:"jwt"`
}

// Actor represents an entity performing an action.
//
// swagger:model Actor
type Actor struct {
	ID string `json:"id" description:"Unique identifier for the actor"`
}

// Object contains details about the object of the action.
//
// swagger:model Object
type Object struct {
	ID           string `json:"id" description:"Unique identifier for the object"`
	URL          []Link `json:"url" description:"List of hyperlinks related to the object"`
	IsNewVersion bool   `json:"isNewVersion" description:"Indicates if this is a new version of the object"`
}

// Link describes a hyperlink related to the object.
//
// swagger:model Link
type Link struct {
	Name      string `json:"name" description:"Name of the link"`
	Type      string `json:"type" description:"Type of the link"`
	Href      string `json:"href" description:"Hyperlink reference URL" validate:"uri"`
	MediaType string `json:"mediaType" description:"Media type of the linked resource"`
	Rel       string `json:"rel" description:"Relationship type of the link"`
}

// Attachment holds additional data related to the action.
//
// swagger:model Attachment
type Attachment struct {
	Type      string  `json:"type" description:"Type of the attachment"`
	Content   Content `json:"content" description:"Content details within the attachment"`
	MediaType string  `json:"mediaType" description:"Media type of the attachment"`
}

// Content describes specific content details in an attachment.
//
// swagger:model Content
type Content struct {
	SourceMimeType      string `json:"source_mimetype,omitempty" description:"MIME type of the source URI"`
	DestinationMimeType string `json:"mimetype" description:"MIME type of the derivative being created"`
	Args                string `json:"args" description:"Arguments used or applicable to the content" validate:"cmdarg"`
	SourceURI           string `json:"source_uri" description:"Source URI from which the content is fetched" validate:"uri"`
	SourceField         string `json:"source_field" description:"Source field from which the media is fetched"`
	DestinationURI      string `json:"destination_uri" description:"Destination URI to where the content is delivered" validate:"uri"`
	FileUploadURI       string `json:"file_upload_uri" description:"File upload URI for uploading the content" validate:"uri"`
}

var (
	// cmdArgPattern validates command-line arguments - allows spaces, blocks URL-specific chars
	cmdArgPattern = regexp.MustCompile(`^[a-zA-Z0-9._\-:\/@ =]+$`)
)

// sanitizeCmdArg validates that a command-line argument is safe to pass to shell commands.
// Uses a whitelist approach - only explicitly allowed characters can pass.
func sanitizeCmdArg(arg string) error {
	if arg == "" {
		return nil
	}

	if !cmdArgPattern.MatchString(arg) {
		return fmt.Errorf("invalid characters in argument: %s", arg)
	}

	return nil
}

// SanitizeShellArg validates that a URI/URL string is safe to pass to shell commands.
// Uses Go's url.Parse() to validate URL structure and ensure it has a scheme.
// The parsed URL is automatically normalized/escaped by url.Parse().
// Use this for: source_uri, destination_uri, file_upload_uri, canonical URLs.
func SanitizeShellArg(arg string) error {
	if arg == "" {
		return nil
	}

	// Parse and validate the URL structure
	// url.Parse automatically handles URL encoding/escaping
	parsedURL, err := url.Parse(arg)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Ensure scheme is present (required for URLs passed to shell commands)
	if parsedURL.Scheme == "" {
		return fmt.Errorf("URL must have a scheme (e.g., https://, private://): %s", arg)
	}

	// The URL is valid and url.Parse has normalized it
	// When we convert back to string, it will be properly escaped
	return nil
}

// validateField validates a single string field based on its validation tag.
// validationType can be: "uri", "cmdarg", "jwt"
// Note: URI/URL fields are normalized in Sanitize() before this is called
func validateField(value, validationType string) error {
	if value == "" {
		return nil
	}

	switch validationType {
	case "uri":
		// URIs are already normalized in Sanitize(), skip validation here
		return nil
	case "cmdarg":
		return sanitizeCmdArg(value)
	case "jwt":
		return isValidAuthHeader(value)
	default:
		return fmt.Errorf("unknown validation type: %s", validationType)
	}
}

func (p *Payload) Sanitize() error {
	return sanitizeAndValidateStruct(reflect.ValueOf(p))
}

func sanitizeAndValidateStruct(v reflect.Value) error {
	// We need to be able to modify the fields, so we need a pointer.
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return nil // Or return an error if you expect only structs
	}

	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// We need to be able to set the value of the field.
		if !field.CanSet() {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			if validateTag := fieldType.Tag.Get("validate"); validateTag != "" {
				originalValue := field.String()
				if originalValue == "" {
					continue
				}

				if validateTag == "uri" {
					normalized, err := normalizeURL(originalValue)
					if err != nil {
						return fmt.Errorf("invalid URI for field '%s': %w", fieldType.Name, err)
					}
					field.SetString(normalized)
				}
				if err := validateField(originalValue, validateTag); err != nil {
					return fmt.Errorf("validation failed for field '%s': %w", fieldType.Name, err)
				}

			}
		case reflect.Struct:
			if err := sanitizeAndValidateStruct(field.Addr()); err != nil {
				return err
			}
		case reflect.Slice:
			for j := 0; j < field.Len(); j++ {
				elem := field.Index(j)
				if elem.Kind() == reflect.Struct {
					if err := sanitizeAndValidateStruct(elem.Addr()); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

// normalizeURL parses and normalizes a URL, ensuring it has a scheme and is properly escaped.
func normalizeURL(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %w", err)
	}

	if parsedURL.Scheme == "" {
		return "", fmt.Errorf("URL must have a scheme (e.g., https://, private://): %s", rawURL)
	}

	// Return the normalized/escaped URL
	return parsedURL.String(), nil
}

// DecodeEventMessage decodes an event message sent by Islandora directly from ActiveMQ.
// It parses the JSON message into a Payload structure and sanitizes all fields.
func DecodeEventMessage(msg []byte) (Payload, error) {
	var p Payload

	if err := json.Unmarshal(msg, &p); err != nil {
		return Payload{}, err
	}

	if err := p.Sanitize(); err != nil {
		return Payload{}, fmt.Errorf("payload validation failed: %w", err)
	}

	return p, nil
}

// DecodeAlpacaMessage decodes an event message transformed by Alpaca from HTTP headers.
// It reads the X-Islandora-Event header (base64-encoded JSON) or constructs a Payload from
// individual HTTP headers (Apix-Ldp-Resource, Accept, Content-Type, X-Islandora-Args).
func DecodeAlpacaMessage(r *http.Request, auth string) (Payload, error) {
	p := Payload{}

	p.Attachment.Content.Args = r.Header.Get("X-Islandora-Args")
	p.Attachment.Content.SourceURI = r.Header.Get("Apix-Ldp-Resource")
	p.Attachment.Content.DestinationMimeType = r.Header.Get("Accept")
	p.Attachment.Content.SourceMimeType = r.Header.Get("Content-Type")
	if p.Attachment.Content.DestinationMimeType == "" {
		p.Attachment.Content.DestinationMimeType = "text/plain"
	}
	p.Authorization = auth
	if r.Method == http.MethodPost {
		return p, nil
	}

	// if the message was sent in the event header, just read it
	message := r.Header.Get("X-Islandora-Event")
	if message != "" {
		j, err := base64.StdEncoding.DecodeString(message)
		if err != nil {
			slog.Error("Error decoding base64", "err", err)
			return p, err
		}
		err = json.Unmarshal(j, &p)
		if err != nil {
			slog.Error("Error unmarshalling event", "err", err)
			return p, err
		}
	}

	slog.Debug("Got message", "msgId", p.Object.ID, "payload.attachment", p.Attachment)
	err := p.getSourceUri(auth)
	if err != nil {
		return p, err
	}

	if err := p.Sanitize(); err != nil {
		return p, fmt.Errorf("payload validation failed: %w", err)
	}

	return p, nil
}

func (p *Payload) getSourceUri(auth string) error {
	if p.Attachment.Content.SourceURI == "" {
		return nil
	}
	slog.Debug("Fetching Content-Type HTTP header for SourceURI mime type", "msgId", p.Object.ID, "SourceURI", p.Attachment.Content.SourceURI)

	client := &http.Client{}

	req, err := http.NewRequest("HEAD", p.Attachment.Content.SourceURI, nil)
	if err != nil {
		slog.Error("Unable to create source URI request", "uri", p.Attachment.Content.SourceURI, "err", err)
		return fmt.Errorf("error creating request for %s", p.Attachment.Content.SourceURI)
	}

	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Unable to get source URI", "uri", p.Attachment.Content.SourceURI, "err", err)
		return fmt.Errorf("error issuing HEAD request on %s", p.Attachment.Content.SourceURI)
	}
	defer resp.Body.Close()

	p.Attachment.Content.SourceMimeType = resp.Header.Get("Content-Type")

	slog.Debug("Got SourceURI mime type", "msgId", p.Object.ID, "SourceMimeType", p.Attachment.Content.SourceMimeType)

	return nil
}

// isValidAuthHeader checks if a string has the basic structure of a JWT
// (three Base64Url-encoded parts separated by periods).
// This is NOT a security check for authentication.
func isValidAuthHeader(authHeader string) error {
	if authHeader == "" {
		return nil
	}

	const bearerPrefix = "bearer "

	if len(authHeader) <= 7 || !strings.EqualFold(authHeader[:7], bearerPrefix) {
		return fmt.Errorf("invalid authorization header: no bearer")
	}

	tokenString := authHeader[7:]
	if tokenString == "" {
		return fmt.Errorf("invalid authorization header: poorly formatted jwt")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid authorization header: incorrect jwt structure")
	}

	for _, part := range parts {
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			return fmt.Errorf("invalid authorization header: bad characters")
		}
	}

	return nil
}
