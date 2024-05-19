package config

import (
	"fmt"
	"mime"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/shlex"
	"github.com/lehigh-university-libraries/scyllaridae/pkg/api"
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

	// Label of the server configuration used for identification.
	//
	// required: false
	QueueName string `yaml:"queueName"`

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

func BuildExecCommand(message api.Payload, c *ServerConfig) (*exec.Cmd, error) {
	mimeType := message.Attachment.Content.SourceMimeType
	if c.MimeTypeFromDestination {
		mimeType = message.Attachment.Content.DestinationMimeType
	}

	if mimeType != "" && !IsAllowedMimeType(mimeType, c.AllowedMimeTypes) {
		return nil, fmt.Errorf("undefined mimeType to build command: %s", mimeType)
	}

	cmdConfig, exists := c.CmdByMimeType[mimeType]
	if !exists {
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
		} else if a == "%destination-mime-ext" {
			a, err := GetMimeTypeExtension(message.Attachment.Content.DestinationMimeType)
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
	if c.ForwardAuth {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SCYLLARIDAE_AUTH=%s", message.Authorization))
	}

	return cmd, nil
}

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

func GetPassedArgs(args string) ([]string, error) {
	passedArgs, err := shlex.Split(args)
	if err != nil {
		return nil, fmt.Errorf("error splitting args %s: %v", args, err)
	}

	// make sure args are OK
	regex, err := regexp.Compile(`^[a-zA-Z0-9._\-:\/@ ]+$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %v", err)
	}
	for _, value := range passedArgs {
		if !regex.MatchString(value) {
			return nil, fmt.Errorf("invalid input for passed arg: %s", value)
		}
	}

	return passedArgs, nil
}
