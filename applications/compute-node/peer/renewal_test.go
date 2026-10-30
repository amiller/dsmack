package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestDrainingGuestDoesNotRenewItsExpiredPaidBinding(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "fixed binding expired", http.StatusForbidden)
	}))
	defer server.Close()
	renew := func() error { return post(server.Client(), server.URL+"/nodes", map[string]string{}, new(any)) }
	if err := renewAdmission(time.Now().Add(-time.Second), renew); err != nil || calls != 0 {
		t.Fatalf("draining guest renewed expired binding: calls=%d err=%v", calls, err)
	}
	if err := renewAdmission(time.Now().Add(time.Minute), renew); err == nil || calls != 1 {
		t.Fatalf("admitting guest lost registration refusal: calls=%d err=%v", calls, err)
	}
}
