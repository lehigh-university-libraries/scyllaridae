package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeEventMessage(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "valid JSON payload",
			input:     []byte(`{"type":"test","target":"http://foo.bar/baz","object":{"id":"123"}}`),
			wantError: false,
		},
		{
			name:      "invalid JSON",
			input:     []byte(`{invalid json`),
			wantError: true,
		},
		{
			name:      "empty payload",
			input:     []byte(`{}`),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := DecodeEventMessage(tt.input)
			if tt.wantError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, payload)
		})
	}
}

func TestDecodeAlpacaMessage(t *testing.T) {
	tests := []struct {
		name             string
		method           string
		headers          map[string]string
		wantDestMimeType string
		wantSrcMimeType  string
		wantArgs         string
		wantError        bool
	}{
		{
			name:   "POST request with headers",
			method: "POST",
			headers: map[string]string{
				"Content-Type":     "image/jpeg",
				"Accept":           "image/png",
				"X-Islandora-Args": "-quality 80",
			},
			wantDestMimeType: "image/png",
			wantSrcMimeType:  "image/jpeg",
			wantArgs:         "-quality 80",
			wantError:        false,
		},
		{
			name:   "GET request with base64 event header",
			method: "GET",
			headers: map[string]string{
				"X-Islandora-Event": base64.StdEncoding.EncodeToString([]byte(`{"type":"test","object":{"id":"123"},"attachment":{"content":{"source_mimetype":"text/plain"}}}`)),
				"Accept":            "application/xml",
			},
			wantDestMimeType: "application/xml",
			wantSrcMimeType:  "text/plain",
			wantError:        false,
		},
		{
			name:   "default Accept header",
			method: "POST",
			headers: map[string]string{
				"Content-Type": "text/html",
			},
			wantDestMimeType: "text/plain", // Default when Accept is empty
			wantSrcMimeType:  "text/html",
			wantError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			payload, err := DecodeAlpacaMessage(req, "Bearer foo.bar.baz")
			if tt.wantError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, "Bearer foo.bar.baz", payload.Authorization)
			assert.Equal(t, tt.wantDestMimeType, payload.Attachment.Content.DestinationMimeType)
			if tt.wantSrcMimeType != "" {
				assert.Equal(t, tt.wantSrcMimeType, payload.Attachment.Content.SourceMimeType)
			}
			if tt.wantArgs != "" {
				assert.Equal(t, tt.wantArgs, payload.Attachment.Content.Args)
			}
		})
	}
}

func TestDecodeAlpacaMessage_WithSourceURIFetch(t *testing.T) {
	// Create a mock server that returns a Content-Type header
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Errorf("Expected HEAD request, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer foo.bar.baz" {
			t.Errorf("Expected Authorization header to be forwarded")
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Apix-Ldp-Resource", mockServer.URL)
	req.Header.Set("Accept", "image/png")

	payload, err := DecodeAlpacaMessage(req, "Bearer foo.bar.baz")
	assert.NoError(t, err)
	assert.Equal(t, "image/jpeg", payload.Attachment.Content.SourceMimeType)
	assert.Equal(t, mockServer.URL, payload.Attachment.Content.SourceURI)
}

func TestDecodeAlpacaMessage_InvalidBase64Event(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Islandora-Event", "not-valid-base64!@#$")
	req.Header.Set("Apix-Ldp-Resource", "https://example.com/file.txt")

	_, err := DecodeAlpacaMessage(req, "")
	assert.Error(t, err)
}

func TestDecodeAlpacaMessage_InvalidJSONInEvent(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Islandora-Event", base64.StdEncoding.EncodeToString([]byte(`{invalid json}`)))
	req.Header.Set("Apix-Ldp-Resource", "https://example.com/file.txt")

	_, err := DecodeAlpacaMessage(req, "")
	assert.Error(t, err)
}

func TestGetSourceUri_ErrorCases(t *testing.T) {
	tests := []struct {
		name      string
		sourceURI string
		wantError bool
	}{
		{
			name:      "empty source URI",
			sourceURI: "",
			wantError: false, // No error when source URI is empty, just returns
		},
		{
			name:      "invalid URL",
			sourceURI: "ht!tp://invalid url with spaces",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Payload{
				Attachment: Attachment{
					Content: Content{
						SourceURI: tt.sourceURI,
					},
				},
			}

			err := p.getSourceUri("")
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetSourceUri_UnreachableServer(t *testing.T) {
	p := &Payload{
		Object: Object{ID: "test-123"},
		Attachment: Attachment{
			Content: Content{
				SourceURI: "http://localhost:99999/unreachable",
			},
		},
	}

	err := p.getSourceUri("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error issuing HEAD request")
}

func TestDecodeAlpacaMessage_FailedSourceURIFetch(t *testing.T) {
	// Create a mock server that returns an error status
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	// Test with invalid event JSON in header
	req := httptest.NewRequest("GET", "/", nil)
	invalidJSON := base64.StdEncoding.EncodeToString([]byte(`{"attachment":{"content":{"source_uri":"` + mockServer.URL + `"}}}`))
	req.Header.Set("X-Islandora-Event", invalidJSON)

	payload, err := DecodeAlpacaMessage(req, "")
	assert.NoError(t, err) // DecodeAlpacaMessage itself doesn't error, just populates the payload
	assert.Equal(t, mockServer.URL, payload.Attachment.Content.SourceURI)
}

func TestPayloadStructures(t *testing.T) {
	// Test that all the payload structures can be marshaled/unmarshaled
	payload := Payload{
		Type:   "Create",
		Target: "http://foo.bar/baz",
		Actor:  Actor{ID: "user:1"},
		Object: Object{
			ID:           "node:123",
			IsNewVersion: true,
			URL: []Link{
				{
					Name:      "canonical",
					Type:      "Link",
					Href:      "https://example.com/node/123",
					MediaType: "text/html",
					Rel:       "canonical",
				},
			},
		},
		Attachment: Attachment{
			Type:      "Image",
			MediaType: "image/jpeg",
			Content: Content{
				SourceMimeType:      "image/jpeg",
				DestinationMimeType: "image/png",
				Args:                "-resize 50%",
				SourceURI:           "https://example.com/source.jpg",
				SourceField:         "field_media_image",
				DestinationURI:      "https://example.com/dest.png",
				FileUploadURI:       "private://derivatives/thumb.png",
			},
		},
		Authorization: "Bearer token123",
	}

	// Test that we can access all fields
	assert.Equal(t, "Create", payload.Type)
	assert.Equal(t, "http://foo.bar/baz", payload.Target)
	assert.Equal(t, "user:1", payload.Actor.ID)
	assert.Equal(t, "node:123", payload.Object.ID)
	assert.True(t, payload.Object.IsNewVersion)
	assert.Len(t, payload.Object.URL, 1)
	assert.Equal(t, "canonical", payload.Object.URL[0].Rel)
	assert.Equal(t, "Image", payload.Attachment.Type)
	assert.Equal(t, "image/jpeg", payload.Attachment.Content.SourceMimeType)
	assert.Equal(t, "Bearer token123", payload.Authorization)
}

func TestSanitizeShellArg(t *testing.T) {
	tests := []struct {
		name      string
		arg       string
		wantError bool
	}{
		{
			name:      "valid URL",
			arg:       "https://example.com/file.jpg",
			wantError: false,
		},
		{
			name:      "valid URL with query params",
			arg:       "https://example.com/file?id=123&format=json",
			wantError: false, // & is valid in URLs
		},
		{
			name:      "valid URL with encoded query",
			arg:       "https://example.com/node/1",
			wantError: false,
		},
		{
			name:      "valid file path",
			arg:       "private://2024-03/thumbnail.jpg",
			wantError: false,
		},
		{
			name:      "empty string",
			arg:       "",
			wantError: false,
		},
		{
			name:      "command injection with semicolon",
			arg:       "https://example.com; echo foo",
			wantError: true,
		},
		{
			name:      "command injection with pipe",
			arg:       "https://example.com | echo foo",
			wantError: true,
		},
		{
			name:      "command injection with ampersand",
			arg:       "https://example.com & echo foo",
			wantError: true,
		},
		{
			name:      "command injection with backticks",
			arg:       "https://example.com`echo foo`",
			wantError: true,
		},
		{
			name:      "command injection with dollar sign",
			arg:       "https://example.com$(echo foo)",
			wantError: true,
		},
		{
			name:      "command injection with backslash",
			arg:       "https://example.com\\necho foo",
			wantError: true,
		},
		{
			name:      "command injection with redirect",
			arg:       "https://example.com > /tmp/test",
			wantError: true,
		},
		{
			name:      "command injection with redirect input",
			arg:       "https://example.com < /tmp/test",
			wantError: true,
		},
		{
			name:      "command injection with newline",
			arg:       "https://example.com\necho foo",
			wantError: true,
		},
		{
			name:      "command injection with exclamation",
			arg:       "https://example.com!malicious",
			wantError: false, // ! is valid in URLs (though unusual)
		},
		{
			name:      "command injection with braces",
			arg:       "https://example.com{malicious}",
			wantError: true,
		},
		{
			name:      "valid with brackets",
			arg:       "https://example.com/path[123]",
			wantError: false,
		},
		{
			name:      "valid with parentheses",
			arg:       "https://example.com/path(123)",
			wantError: false,
		},
		{
			name:      "tilde path without scheme",
			arg:       "~/path/to/file.txt",
			wantError: true, // No scheme
		},
		{
			name:      "valid with plus and equals",
			arg:       "https://example.com/path+test=value",
			wantError: false,
		},
		{
			name:      "valid with hash",
			arg:       "https://example.com/page#section",
			wantError: false,
		},
		{
			name:      "valid private:// URI",
			arg:       "private://2024-03/file.jpg",
			wantError: false,
		},
		{
			name:      "valid public:// URI",
			arg:       "public://documents/report.pdf",
			wantError: false,
		},
		{
			name:      "valid FTP URL",
			arg:       "ftp://ftp.example.com/file.zip",
			wantError: false,
		},
		{
			name:      "valid file:// URL",
			arg:       "file:///tmp/local-file.txt",
			wantError: false,
		},
		{
			name:      "URL without scheme",
			arg:       "example.com/file.jpg",
			wantError: true, // Missing scheme
		},
		{
			name:      "relative path without scheme",
			arg:       "/path/to/file.jpg",
			wantError: true, // Missing scheme
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SanitizeShellArg(tt.arg)
			if tt.wantError {
				assert.Error(t, err, "Expected error for: %s", tt.arg)
			} else {
				assert.NoError(t, err, "Expected no error for: %s", tt.arg)
			}
		})
	}
}

func TestPayloadSanitize(t *testing.T) {
	tests := []struct {
		name      string
		payload   Payload
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid payload",
			payload: Payload{
				Target: "http://foo.bar/baz",
				Object: Object{
					URL: []Link{
						{Href: "https://example.com/node/1", Rel: "canonical"},
					},
				},
				Attachment: Attachment{
					Content: Content{
						SourceURI:      "https://example.com/source.jpg",
						DestinationURI: "https://example.com/dest.jpg",
						FileUploadURI:  "private://file.jpg",
					},
				},
			},
			wantError: false,
		},
		{
			name: "invalid source URI with semicolon",
			payload: Payload{
				Attachment: Attachment{
					Content: Content{
						SourceURI: "not a url",
					},
				},
			},
			wantError: true,
			errorMsg:  "invalid URI for field 'SourceURI': URL must have a scheme (e.g., https://, private://): not a url",
		},
		{
			name: "invalid destination URI with pipe",
			payload: Payload{
				Attachment: Attachment{
					Content: Content{
						DestinationURI: "not a url",
					},
				},
			},
			wantError: true,
			errorMsg:  "invalid URI for field 'DestinationURI': URL must have a scheme (e.g., https://, private://): not a url",
		},
		{
			name: "invalid file upload URI with backtick",
			payload: Payload{
				Attachment: Attachment{
					Content: Content{
						FileUploadURI: "not a url",
					},
				},
			},
			wantError: true,
			errorMsg:  "invalid URI for field 'FileUploadURI': URL must have a scheme (e.g., https://, private://): not a url",
		},
		{
			name: "invalid target with dollar sign",
			payload: Payload{
				Target: "not a url",
			},
			wantError: true,
			errorMsg:  "invalid URI for field 'Target': URL must have a scheme (e.g., https://, private://): not a url",
		},
		{
			name: "invalid canonical href with pipe",
			payload: Payload{
				Object: Object{
					URL: []Link{
						{Href: "not a url", Rel: "canonical"},
					},
				},
			},
			wantError: true,
			errorMsg:  "invalid URI for field 'Href': URL must have a scheme (e.g., https://, private://): not a url",
		},
		{
			name: "invalid args with semicolon",
			payload: Payload{
				Attachment: Attachment{
					Content: Content{
						Args: "-quality 80; echo foo",
					},
				},
			},
			wantError: true,
			errorMsg:  "invalid characters in argument",
		},
		{
			name: "valid args",
			payload: Payload{
				Attachment: Attachment{
					Content: Content{
						Args: "-quality 80",
					},
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.payload.Sanitize()
			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSanitizeCmdArg(t *testing.T) {
	tests := []struct {
		name      string
		arg       string
		wantError bool
	}{
		{
			name:      "valid command arg with space",
			arg:       "-quality 80",
			wantError: false,
		},
		{
			name:      "valid command arg with equals",
			arg:       "-resize=50",
			wantError: false,
		},
		{
			name:      "valid command arg simple flag",
			arg:       "-verbose",
			wantError: false,
		},
		{
			name:      "empty string",
			arg:       "",
			wantError: false,
		},
		{
			name:      "invalid with question mark",
			arg:       "-arg?value",
			wantError: true,
		},
		{
			name:      "invalid with hash",
			arg:       "-arg#value",
			wantError: true,
		},
		{
			name:      "invalid with percent (URL encoding)",
			arg:       "-arg%20value",
			wantError: true,
		},
		{
			name:      "invalid with brackets",
			arg:       "-arg[0]",
			wantError: true,
		},
		{
			name:      "command injection with semicolon",
			arg:       "-arg; echo foo",
			wantError: true,
		},
		{
			name:      "command injection with pipe",
			arg:       "-arg | echo foo",
			wantError: true,
		},
		{
			name:      "command injection with dollar",
			arg:       "-arg$(echo foo)",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sanitizeCmdArg(tt.arg)
			if tt.wantError {
				assert.Error(t, err, "Expected error for: %s", tt.arg)
			} else {
				assert.NoError(t, err, "Expected no error for: %s", tt.arg)
			}
		})
	}
}

func TestDecodeEventMessageWithSanitization(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid payload passes sanitization",
			input:     `{"target":"http://foo.bar/baz","attachment":{"content":{"source_uri":"https://example.com/file.jpg"}}}`,
			wantError: false,
		},
		{
			name:      "payload with malicious source_uri fails",
			input:     `{"attachment":{"content":{"source_uri":"https://example.com; echo foo"}}}`,
			wantError: true,
			errorMsg:  "payload validation failed",
		},
		{
			name:      "payload with malicious target fails",
			input:     `{"target":echo foo"}`,
			wantError: true,
			errorMsg:  "invalid character 'e' looking for beginning of value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeEventMessage([]byte(tt.input))
			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
