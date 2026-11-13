package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestGuestAttestsOnceThenRenewsItsLeaseAndReattestsOnlyWhenTheBrokerForgetsIt(t *testing.T) {
	registered, refreshes, registrations := false, 0, 0
	var refreshErr, registerErr error
	refresh := func() error { refreshes++; return refreshErr }
	register := func() error { registrations++; return registerErr }
	for i := 0; i < 3; i++ {
		if err := renewLease(&registered, refresh, register); err != nil {
			t.Fatal(err)
		}
	}
	if registrations != 1 || refreshes != 2 {
		t.Fatalf("idle ticks attested: registrations=%d refreshes=%d", registrations, refreshes)
	}
	refreshErr = errors.New("unknown guest")
	if err := renewLease(&registered, refresh, register); err != nil || registrations != 2 || !registered {
		t.Fatalf("forgotten guest did not register again: %v", err)
	}
	registerErr = errors.New("run expired")
	err := renewLease(&registered, refresh, register)
	if err == nil || !strings.Contains(err.Error(), "unknown guest") || !errors.Is(err, registerErr) || registered {
		t.Fatalf("both failures must be reported: %v", err)
	}
}
