package restapi

import (
	"encoding/json"
	"io"
	"net/http"
)

// HandlerFunc is like [http.HandlerFunc], but returns a status code and an error.
type HandlerFunc func(w http.ResponseWriter, r *http.Request) (status int, err error)

// EncodeResponse sets the Content-Type header field to application/json, and writes
// to the response writer with the given status code and data encoded as JSON.
//
// If data is nil, only the status code is written and no data is encoded.
//
// If data is of type [io.Reader] or []byte, it is assumed to be encoded JSON
// and is written directly to the response writer.
func EncodeResponse(w http.ResponseWriter, status int, data any) (int, error) {
	if data == nil {
		w.WriteHeader(status)
		return status, nil
	}
	w.Header()["Content-Type"] = []string{"application/json"}
	w.WriteHeader(status)
	var err error
	switch v := data.(type) {
	case io.Reader:
		_, err = io.Copy(w, v)
	case *[]byte:
		_, err = w.Write(*v)
	case []byte:
		_, err = w.Write(v)
	default:
		err = json.NewEncoder(w).Encode(v)
	}
	return status, err
}

// DecodeRequest decodes the request body as JSON into the provided value.
func DecodeRequest(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
