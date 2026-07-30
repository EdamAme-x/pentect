package pentectplugin

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
)

const Schema = "pentect.plugin.v1"

func ConfigPath() string { return os.Getenv("PENTECT_PLUGIN_CONFIG") }
func CachePath() string  { return os.Getenv("PENTECT_PLUGIN_CACHE_DIR") }

type Request struct {
	Schema  string          `json:"schema"`
	ID      uint64          `json:"id"`
	Type    string          `json:"type"`
	Stage   string          `json:"stage,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Context json.RawMessage `json:"context,omitempty"`
}

type Response struct {
	Schema  string `json:"schema"`
	ID      uint64 `json:"id"`
	Type    string `json:"type"`
	Action  string `json:"action,omitempty"`
	Outcome string `json:"outcome,omitempty"`
	Payload any    `json:"payload,omitempty"`
	Message string `json:"message,omitempty"`
	Spans   any    `json:"spans,omitempty"`
}

func Next(id uint64) Response {
	return Response{Schema: Schema, ID: id, Type: "result", Action: "next"}
}

func Block(id uint64, message string) Response {
	return Response{Schema: Schema, ID: id, Type: "result", Action: "stop", Outcome: "block", Message: message}
}

func Serve(handler func(Request) (Response, error)) error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request Request
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			return err
		}
		if request.Schema != Schema {
			return errors.New("unsupported Pentect plugin schema")
		}
		var response Response
		var err error
		if request.Type == "initialize" {
			response = Response{Schema: Schema, ID: request.ID, Type: "initialized"}
		} else {
			response, err = handler(request)
			if err != nil {
				return err
			}
		}
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
	return scanner.Err()
}
