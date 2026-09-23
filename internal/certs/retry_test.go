package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestRateLimitReturnsInsteadOfSleepingUntilRetryAfter(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		if r.Method == "HEAD" {
			return
		}
		if r.Method == "GET" {
			fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`, server.URL+"/nonce", server.URL+"/account", server.URL+"/order")
			return
		}
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates; retry after one hour"}`)
	}))
	defer server.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Hostname: "example.test", InstallDir: t.TempDir(), StateDir: t.TempDir()}
	if err := o.defaults(); err != nil {
		t.Fatal(err)
	}
	client := o.newACME(key, server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = client.Register(ctx, &acme.Account{}, acme.AcceptTOS)
	if ctx.Err() != nil {
		t.Fatalf("certificate client waited until cancellation instead of reporting rate limit: %v", err)
	}
	var problem *acme.Error
	if !errors.As(err, &problem) || problem.StatusCode != 429 {
		t.Fatalf("wanted immediate rate-limit error, got %v", err)
	}
}

func TestCertificateRetriesAreBoundedAndRespectServerDelay(t *testing.T) {
	for _, tc := range []struct {
		name            string
		status, attempt int
		after           string
		want            time.Duration
	}{
		{"rate limit", 429, 1, "3600", 0},
		{"transient", 503, 1, "", time.Second},
		{"last retry", 503, 4, "", 0},
		{"short server delay", 503, 1, "5", 5 * time.Second},
		{"long server delay", 503, 1, "3600", 0},
		{"future server date", 503, 1, time.Now().Add(time.Hour).UTC().Format(http.TimeFormat), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Response{StatusCode: tc.status, Header: make(http.Header)}
			r.Header.Set("Retry-After", tc.after)
			if got := certificateRetryBackoff(tc.attempt, nil, r); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}
