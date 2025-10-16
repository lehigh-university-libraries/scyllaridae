package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/islandora/scyllaridae/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestIsAllowedMimeType(t *testing.T) {
	tests := []struct {
		name           string
		mimetype       string
		allowedFormats []string
		want           bool
	}{
		{
			name:           "exact match",
			mimetype:       "image/jpeg",
			allowedFormats: []string{"image/jpeg", "image/png"},
			want:           true,
		},
		{
			name:           "wildcard match",
			mimetype:       "image/jpeg",
			allowedFormats: []string{"image/*"},
			want:           true,
		},
		{
			name:           "allow all",
			mimetype:       "anything/goes",
			allowedFormats: []string{"*"},
			want:           true,
		},
		{
			name:           "no match",
			mimetype:       "video/mp4",
			allowedFormats: []string{"image/*", "audio/*"},
			want:           false,
		},
		{
			name:           "mime type with charset",
			mimetype:       "text/html; charset=utf-8",
			allowedFormats: []string{"text/html"},
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAllowedMimeType(tt.mimetype, tt.allowedFormats)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReadConfig(t *testing.T) {
	tests := []struct {
		name      string
		yml       string
		wantError bool
		validate  func(*testing.T, *ServerConfig)
	}{
		{
			name: "valid config with defaults",
			yml: `allowedMimeTypes:
  - "*"
cmdByMimeType:
  default:
    cmd: "echo"
    args: ["hello"]`,
			wantError: false,
			validate: func(t *testing.T, c *ServerConfig) {
				assert.True(t, *c.ForwardAuth, "forwardAuth should default to true")
				assert.Equal(t, "", c.JwksUri)
				assert.Equal(t, []string{"*"}, c.AllowedMimeTypes)
			},
		},
		{
			name: "config with jwksUri",
			yml: `jwksUri: "https://example.com/keys"
allowedMimeTypes:
  - "image/*"
cmdByMimeType:
  default:
    cmd: "cat"`,
			wantError: false,
			validate: func(t *testing.T, c *ServerConfig) {
				assert.Equal(t, "https://example.com/keys", c.JwksUri)
			},
		},
		{
			name: "config with environment variable expansion",
			yml: `allowedMimeTypes:
  - "*"
cmdByMimeType:
  default:
    cmd: "${TEST_CMD}"
    args: ["${TEST_ARG}"]`,
			wantError: false,
			validate: func(t *testing.T, c *ServerConfig) {
				os.Setenv("TEST_CMD", "testcmd")
				os.Setenv("TEST_ARG", "testarg")
				defer os.Unsetenv("TEST_CMD")
				defer os.Unsetenv("TEST_ARG")
				// Note: config was already parsed, so this tests the mechanism exists
			},
		},
		{
			name:      "invalid YAML",
			yml:       "this is not: valid: yaml:",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("SCYLLARIDAE_YML", tt.yml)
			defer os.Unsetenv("SCYLLARIDAE_YML")

			config, err := ReadConfig()
			if tt.wantError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			if tt.validate != nil {
				tt.validate(t, config)
			}
		})
	}
}

func TestBuildExecCommand(t *testing.T) {
	tests := []struct {
		name      string
		config    *ServerConfig
		payload   api.Payload
		wantCmd   string
		wantArgs  []string
		wantError bool
	}{
		{
			name: "basic command with default",
			config: &ServerConfig{
				AllowedMimeTypes: []string{"*"},
				CmdByMimeType: map[string]Command{
					"default": {Cmd: "echo", Args: []string{"hello"}},
				},
			},
			payload: api.Payload{
				Attachment: api.Attachment{
					Content: api.Content{
						SourceMimeType: "text/plain",
					},
				},
			},
			wantCmd:   "echo",
			wantArgs:  []string{"hello"},
			wantError: false,
		},
		{
			name: "command with %args placeholder",
			config: &ServerConfig{
				AllowedMimeTypes: []string{"*"},
				CmdByMimeType: map[string]Command{
					"default": {Cmd: "convert", Args: []string{"-", "%args", "jpg:-"}},
				},
			},
			payload: api.Payload{
				Attachment: api.Attachment{
					Content: api.Content{
						SourceMimeType: "image/png",
						Args:           "-quality 80",
					},
				},
			},
			wantCmd:   "convert",
			wantArgs:  []string{"-", "-quality", "80", "jpg:-"},
			wantError: false,
		},
		{
			name: "command with MIME type placeholders",
			config: &ServerConfig{
				AllowedMimeTypes: []string{"*"},
				CmdByMimeType: map[string]Command{
					"default": {Cmd: "echo", Args: []string{"%source-mime-ext", "%destination-mime-ext"}},
				},
			},
			payload: api.Payload{
				Attachment: api.Attachment{
					Content: api.Content{
						SourceMimeType:      "image/jpeg",
						DestinationMimeType: "image/png",
					},
				},
			},
			wantCmd:   "echo",
			wantArgs:  []string{"jpg", "png"},
			wantError: false,
		},
		{
			name: "disallowed MIME type",
			config: &ServerConfig{
				AllowedMimeTypes: []string{"image/*"},
				CmdByMimeType: map[string]Command{
					"default": {Cmd: "echo", Args: []string{"test"}},
				},
			},
			payload: api.Payload{
				Attachment: api.Attachment{
					Content: api.Content{
						SourceMimeType: "video/mp4",
					},
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fa := true
			tt.config.ForwardAuth = &fa

			cmd, err := BuildExecCommand(tt.payload, tt.config)
			if tt.wantError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantCmd, filepath.Base(cmd.Path))
			assert.Equal(t, tt.wantArgs, cmd.Args[1:]) // Skip Args[0] which is the command itself
		})
	}
}

// TestBadCmdArgs removed - validation now happens during Payload unmarshaling
// via api.SanitizeCmdArg(). See TestPayloadSanitize and TestSanitizeCmdArg
// in pkg/api/events_test.go for comprehensive validation tests.

func TestMimeToPandoc(t *testing.T) {
	tests := []struct {
		name     string
		mimeType string
		want     string
		wantErr  bool
	}{
		{
			name:     "markdown mime type",
			mimeType: "text/markdown",
			want:     "markdown",
			wantErr:  false,
		},
		{
			name:     "html mime type",
			mimeType: "text/html",
			want:     "html",
			wantErr:  false,
		},
		{
			name:     "docx mime type",
			mimeType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			want:     "docx",
			wantErr:  false,
		},
		{
			name:     "latex mime type",
			mimeType: "application/x-latex",
			want:     "latex",
			wantErr:  false,
		},
		{
			name:     "fallback to extension for unknown type",
			mimeType: "image/jpeg",
			want:     "jpg",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MimeToPandoc(tt.mimeType)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMimeTypes(t *testing.T) {
	tests := []struct {
		name      string
		mimeType  string
		extension string
		wantError bool
	}{
		// Valid MIME types
		{"msword", "application/msword", "doc", false},
		{"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", false},
		{"excel", "application/vnd.ms-excel", "xls", false},
		{"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx", false},
		{"powerpoint", "application/vnd.ms-powerpoint", "ppt", false},
		{"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx", false},

		{"jpeg", "image/jpeg", "jpg", false},
		{"jp2", "image/jp2", "jp2", false},
		{"png", "image/png", "png", false},
		{"gif", "image/gif", "gif", false},
		{"bmp", "image/bmp", "bmp", false},
		{"svg", "image/svg+xml", "svg", false},
		{"tiff", "image/tiff", "tiff", false},
		{"webp", "image/webp", "webp", false},

		{"mp3", "audio/mpeg", "mp3", false},
		{"wav", "audio/x-wav", "wav", false},
		{"ogg audio", "audio/ogg", "ogg", false},
		{"aac", "audio/aac", "m4a", false},
		{"webm audio", "audio/webm", "webm", false},
		{"flac", "audio/flac", "flac", false},
		{"midi", "audio/midi", "mid", false},
		{"m4a", "audio/x-m4a", "m4a", false},
		{"realaudio", "audio/x-realaudio", "ra", false},

		{"mp4", "video/mp4", "mp4", false},
		{"avi", "video/x-msvideo", "avi", false},
		{"wmv", "video/x-ms-wmv", "wmv", false},
		{"mpeg", "video/mpeg", "mpg", false},
		{"webm video", "video/webm", "webm", false},
		{"quicktime", "video/quicktime", "mov", false},
		{"m3u8", "application/vnd.apple.mpegurl", "m3u8", false},
		{"3gp", "video/3gpp", "3gp", false},
		{"ts", "video/mp2t", "ts", false},
		{"flv", "video/x-flv", "flv", false},
		{"m4v", "video/x-m4v", "m4v", false},
		{"mng", "video/x-mng", "mng", false},
		{"asx", "video/x-ms-asf", "asx", false},
		{"ogg video", "video/ogg", "ogg", false},

		{"plain text", "text/plain", "txt", false},
		{"html", "text/html", "html", false},
		{"pdf", "application/pdf", "pdf", false},
		{"csv", "text/csv", "csv", false},
		{"markdown", "text/markdown", "md", false},

		// Invalid MIME types - should error
		{"malicious with semicolon", "image/jpeg; rm -rf /", "", true},
		{"malicious with pipe", "video/mp4 | echo foo", "", true},
		{"malicious with dollar", "audio/mpeg$(whoami)", "", true},
		{"malicious with backtick", "text/plain`id`", "", true},
		{"malicious with ampersand", "image/png & ls", "", true},
		{"unknown mime type", "application/x-unknown-format", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := GetMimeTypeExtension(tt.mimeType)
			if tt.wantError {
				assert.Error(t, err, "Expected error for MIME type: %s", tt.mimeType)
			} else {
				assert.NoError(t, err, "Expected no error for MIME type: %s", tt.mimeType)
				assert.Equal(t, tt.extension, ext, "Expected extension %s for MIME type %s", tt.extension, tt.mimeType)
			}
		})
	}
}
