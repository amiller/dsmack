package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistrationErrorsRetainResponseAndRefusalsDoNotRetry(t *testing.T) {
	for _, status := range []int{403, 408, 429, 500, 502, 503} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			w.Write([]byte("named registration failure"))
		}))
		err := post(server.Client(), server.URL+"/nodes", map[string]string{}, new(any))
		server.Close()
		var response *brokerHTTPError
		if !errors.As(err, &response) || response.Status != status || response.Path != "/nodes" || response.Body != "named registration failure" {
			t.Fatalf("missing HTTP failure: %v", err)
		}
		if transientRegistration(err) != (status != 403) {
			t.Fatalf("retry policy for HTTP %d", status)
		}
	}
}
