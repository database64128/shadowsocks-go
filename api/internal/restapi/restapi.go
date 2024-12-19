package restapi

import (
	"encoding/json"
	"net/http"
)

// HandlerFunc is like [http.HandlerFunc], but returns a status code and an error.
type HandlerFunc func(w http.ResponseWriter, r *http.Request) (status int, err error)

// EncodeResponse sets the Content-Type header field to application/json, and writes
// to the response writer with the given status code and data encoded as JSON.
//
// If data is nil, the status code is written and no data is encoded.
func EncodeResponse(w http.ResponseWriter, status int, data any) (int, error) {
	if data == nil {
		w.WriteHeader(status)
		return status, nil
	}
	w.Header()["Content-Type"] = []string{"application/json"}
	w.WriteHeader(status)
	return status, json.NewEncoder(w).Encode(data)
}

// DecodeRequest decodes the request body as JSON into the provided value.
func DecodeRequest(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
