package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/google/shlex"
	"github.com/islandora/scyllaridae/pkg/api"
	yaml "gopkg.in/yaml.v3"
)

// ServerConfig defines server-specific configurations.
//
// swagger:model ServerConfig
type ServerConfig struct {
	// Indicates whether the authentication header should be forwarded.
	//
	// required: false
	// default: true
	ForwardAuth *bool `yaml:"forwardAuth,omitempty"`

	// The URI for the JSON Web Key Set (JWKS) endpoint.
	// If empty, JWT verification will be skipped.
	//
	// required: false
	JwksUri string `yaml:"jwksUri,omitempty"`

	// List of MIME types allowed for processing.
	//
	// required: false
	AllowedMimeTypes []string `yaml:"allowedMimeTypes"`

	// Commands and arguments ran by MIME type.
	//
	// required: false
	CmdByMimeType map[string]Command `yaml:"cmdByMimeType"`

	// Commands and arguments ran by MIME type based on the destination file format
	//
	// required: false
	MimeTypeFromDestination bool `yaml:"mimeTypeFromDestination,omitempty"`
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

// IsAllowedMimeType checks if a given MIME type is allowed based on the configured formats.
// It supports exact matches, wildcard patterns (e.g., "image/*"), and the special "*" value for all types.
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
		if format == strings.Split(mimetype, ";")[0] {
			return true
		}
	}
	return false
}

// ReadConfig reads and parses the scyllaridae configuration from the environment.
// It first checks the SCYLLARIDAE_YML environment variable for inline YAML content,
// then falls back to reading from the file path specified in SCYLLARIDAE_YML_PATH.
// Environment variables in the YAML content are expanded using os.ExpandEnv.
func ReadConfig() (*ServerConfig, error) {
	var (
		y   []byte
		err error
	)
	yml := os.Getenv("SCYLLARIDAE_YML")
	if yml != "" {
		y = []byte(yml)
	} else {
		yp := os.Getenv("SCYLLARIDAE_YML_PATH")
		if yp == "" {
			return nil, errors.New("need to specify the path to scyllaridae.yml with the environment variable SCYLLARIDAE_YML_PATH")
		}
		y, err = os.ReadFile(yp)
		if err != nil {
			return nil, err
		}
	}

	expanded := os.ExpandEnv(string(y))

	slog.Debug("scyllaridae yaml set", "yaml", expanded)

	var c ServerConfig
	err = yaml.Unmarshal([]byte(expanded), &c)
	if err != nil {
		return nil, err
	}

	if c.ForwardAuth == nil {
		fa := true
		c.ForwardAuth = &fa
	}

	return &c, nil
}

// BuildExecCommand constructs an exec.Cmd based on the event payload and server configuration.
// It selects the appropriate command based on MIME type and replaces special placeholder variables
// in the arguments (e.g., %args, %source-uri, %destination-uri, %canonical).
func BuildExecCommand(message api.Payload, c *ServerConfig) (*exec.Cmd, error) {
	slog.Debug("Building exec command", "msgId", message.Object.ID, "payloadType", message.Type, "target", message.Target)

	mimeType := message.Attachment.Content.SourceMimeType
	if c.MimeTypeFromDestination {
		mimeType = message.Attachment.Content.DestinationMimeType
	}

	if mimeType != "" && !IsAllowedMimeType(mimeType, c.AllowedMimeTypes) {
		return nil, fmt.Errorf("undefined mimeType to build command: %s", mimeType)
	}

	slog.Debug("Mapping mimetype to a command", "msgId", message.Object.ID, "mimeType", mimeType)

	cmdConfig, exists := c.CmdByMimeType[mimeType]
	if !exists {
		slog.Debug("Using default command")
		cmdConfig = c.CmdByMimeType["default"]
	}

	args := []string{}
	for _, a := range cmdConfig.Args {
		// if we have the special value of %args
		// replace it with the args passed by the event
		if a == "%args" {
			if message.Attachment.Content.Args != "" {
				passedArgs, err := GetPassedArgs(message.Attachment.Content.Args)
				if err != nil {
					return nil, fmt.Errorf("could not parse args: %v", err)
				}
				args = append(args, passedArgs...)
			}
			// if we have the special value of %source-mime-ext
			// replace it with the source mimetype extension
		} else if a == "%source-mime-ext" {
			a, err := GetMimeTypeExtension(message.Attachment.Content.SourceMimeType)
			if err != nil {
				return nil, fmt.Errorf("unknown mime extension: %s", message.Attachment.Content.SourceMimeType)
			}

			args = append(args, a)
			// if we have the special value of %destination-mime-ext
			// replace it with the source mimetype extension
		} else if a == "%destination-mime-ext" || a == "%destination-mime-ext:-" {
			dash := false
			if a == "%destination-mime-ext:-" {
				dash = true
			}
			a, err := GetMimeTypeExtension(message.Attachment.Content.DestinationMimeType)
			if err != nil {
				return nil, fmt.Errorf("unknown mime extension: %s", message.Attachment.Content.DestinationMimeType)
			}
			if dash {
				a = fmt.Sprintf("%s:-", a)
			}
			args = append(args, a)
		} else if a == "%source-mime-pandoc" {
			a, err := MimeToPandoc(message.Attachment.Content.SourceMimeType)
			if err != nil {
				return nil, fmt.Errorf("unknown mime extension: %s", message.Attachment.Content.SourceMimeType)
			}

			args = append(args, a)
		} else if a == "%destination-mime-pandoc" {
			a, err := MimeToPandoc(message.Attachment.Content.DestinationMimeType)
			if err != nil {
				return nil, fmt.Errorf("unknown mime extension: %s", message.Attachment.Content.DestinationMimeType)
			}
			args = append(args, a)

		} else if a == "%target" {
			args = append(args, message.Target)
		} else if a == "%source-uri" {
			args = append(args, message.Attachment.Content.SourceURI)
		} else if a == "%file-upload-uri" {
			args = append(args, message.Attachment.Content.FileUploadURI)
		} else if a == "%destination-uri" {
			args = append(args, message.Attachment.Content.DestinationURI)
		} else if a == "%canonical" {
			for _, u := range message.Object.URL {
				if u.Rel == "canonical" {
					args = append(args, u.Href)
					break
				}
			}
		} else {
			args = append(args, a)
		}
	}

	cmd := exec.Command(cmdConfig.Cmd, args...)
	cmd.Env = os.Environ()
	// pass the Authorization header as an environment variable to avoid logging it
	if *c.ForwardAuth {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SCYLLARIDAE_AUTH=%s", message.Authorization))
	}

	return cmd, nil
}

// GetMimeTypeExtension returns the file extension for a given MIME type.
// It first checks a custom mapping for common MIME types, then falls back to
// the standard library's mime.ExtensionsByType.
func GetMimeTypeExtension(mimeType string) (string, error) {
	// since the std mimetype -> extension conversion returns a list
	// we need to override the default extension to use
	// it also is missing some mimetypes
	mimeToExtension := map[string]string{
		"application/msword":            "doc",
		"application/vnd.ms-excel":      "xls",
		"application/vnd.ms-powerpoint": "ppt",

		"image/svg+xml": "svg",
		"image/webp":    "webp",
		"image/jp2":     "jp2",
		"image/bmp":     "bmp",

		"video/mp4":                     "mp4",
		"video/quicktime":               "mov",
		"video/x-ms-asf":                "asx",
		"video/mp2t":                    "ts",
		"video/mpeg":                    "mpg",
		"application/vnd.apple.mpegurl": "m3u8",
		"video/3gpp":                    "3gp",
		"video/x-m4v":                   "m4v",
		"video/x-msvideo":               "avi",
		"video/ogg":                     "ogg",

		"audio/ogg":         "ogg",
		"audio/webm":        "webm",
		"audio/flac":        "flac",
		"audio/aac":         "m4a",
		"audio/mpeg":        "mp3",
		"audio/x-m4a":       "m4a",
		"audio/x-realaudio": "ra",
		"audio/midi":        "mid",
		"audio/x-wav":       "wav",

		"text/markdown": "md",
	}
	cleanMimeType := strings.TrimSpace(strings.ToLower(mimeType))
	if ext, ok := mimeToExtension[cleanMimeType]; ok {
		return ext, nil
	}

	extensions, err := mime.ExtensionsByType(mimeType)
	if err != nil || len(extensions) == 0 {
		return "", fmt.Errorf("unknown mime extension: %s", mimeType)
	}

	return strings.TrimPrefix(extensions[len(extensions)-1], "."), nil
}

// GetPassedArgs parses command-line arguments from a string using shell-style parsing.
// Note: Validation happens during event unmarshaling via api.SanitizeCmdArg(),
// so this function only needs to split the arguments.
func GetPassedArgs(args string) ([]string, error) {
	passedArgs, err := shlex.Split(args)
	if err != nil {
		return nil, fmt.Errorf("error splitting args %s: %v", args, err)
	}

	return passedArgs, nil
}

func (c *ServerConfig) GetFileStream(r *http.Request, message api.Payload, auth string) (io.ReadCloser, int, error) {
	if r.Method == http.MethodPost {
		slog.Debug("Streaming body directly to command", "msgId", message.Object.ID)
		return r.Body, http.StatusOK, nil
	}
	if message.Attachment.Content.SourceURI == "" {
		slog.Debug("No source URI to stream", "msgId", message.Object.ID)
		return nil, http.StatusOK, nil
	}

	slog.Debug("Opening SourceURI for streaming", "msgId", message.Object.ID, "SourceURI", message.Attachment.Content.SourceURI)
	req, err := http.NewRequest("GET", message.Attachment.Content.SourceURI, nil)
	if err != nil {
		slog.Error("Error building request to fetch source file contents", "err", err)
		return nil, http.StatusBadRequest, fmt.Errorf("bad request")
	}
	if *c.ForwardAuth {
		req.Header.Set("Authorization", auth)
	}
	sourceResp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Error("Error fetching source file contents", "err", err)
		return nil, http.StatusInternalServerError, fmt.Errorf("internal error")
	}
	if sourceResp.StatusCode != http.StatusOK {
		slog.Error("SourceURI sent a bad status code", "code", sourceResp.StatusCode, "uri", message.Attachment.Content.SourceURI)
		return nil, http.StatusFailedDependency, fmt.Errorf("failed dependency")
	}

	slog.Debug("HTTP request created for source", "msgId", message.Object.ID, "url", req.URL.String())

	return sourceResp.Body, http.StatusOK, nil
}

// MimeToPandoc converts a MIME type to its corresponding Pandoc format string.
// It returns the Pandoc format name if found, otherwise falls back to GetMimeTypeExtension.
func MimeToPandoc(mimeType string) (string, error) {
	mapping := map[string]string{
		"text/x-bibtex":                           "bibtex",
		"text/x-biblatex":                         "biblatex",
		"application/xml":                         "bits",
		"text/x-commonmark":                       "commonmark",
		"text/x-commonmark+extensions":            "commonmark_x",
		"text/x-creole":                           "creole",
		"application/vnd.citationstyles.csl+json": "csljson",
		"text/csv":                                "csv",
		"text/tab-separated-values":               "tsv",
		"text/x-djot":                             "djot",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
		"application/docbook+xml":                 "docbook",
		"application/xml-dokuwiki":                "dokuwiki",
		"application/vnd.endnote+xml":             "endnotexml",
		"application/epub+zip":                    "epub",
		"application/x-fictionbook+xml":           "fb2",
		"text/x-gfm":                              "gfm",
		"text/x-haddock":                          "haddock",
		"text/html":                               "html",
		"application/x-ipynb+json":                "ipynb",
		"application/jats+xml":                    "jats",
		"text/x-jira":                             "jira",
		"application/json":                        "json",
		"application/x-latex":                     "latex",
		"text/markdown":                           "markdown",
		"text/markdown+mmd":                       "markdown_mmd",
		"text/markdown+phpextra":                  "markdown_phpextra",
		"text/markdown+strict":                    "markdown_strict",
		"text/x-mediawiki":                        "mediawiki",
		"application/x-troff-man":                 "man",
		"text/x-muse":                             "muse",
		"application/vnd.haskell.native":          "native",
		"application/vnd.oasis.opendocument.text": "odt",
		"application/x-opml+xml":                  "opml",
		"text/x-org":                              "org",
		"application/x-research-info-systems":     "ris",
		"application/rtf":                         "rtf",
		"text/x-rst":                              "rst",
		"text/x-txt2tags":                         "t2t",
		"text/x-textile":                          "textile",
		"text/x-tikiwiki":                         "tikiwiki",
		"text/x-twiki":                            "twiki",
		"application/x-typst":                     "typst",
		"text/x-vimwiki":                          "vimwiki",
	}

	pandoc, ok := mapping[mimeType]
	if !ok {
		return GetMimeTypeExtension(mimeType)
	}
	return pandoc, nil
}
