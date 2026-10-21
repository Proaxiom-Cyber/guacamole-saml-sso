package webpreview

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func send(r *Relay, path, method, agent string, cookie *http.Cookie, body any, origin string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	q := httptest.NewRequest(method, r.Origin+path, bytes.NewReader(b))
	if agent != "" {
		q.Header.Set("Authorization", "Bearer "+agent)
	}
	if cookie != nil {
		q.AddCookie(cookie)
	}
	if origin != "" {
		q.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, q)
	return w
}
func pair(t *testing.T, r *Relay, secret string) *http.Cookie {
	t.Helper()
	w := send(r, "/agent/sessions", "POST", "", nil, map[string]string{"secret": secret}, "")
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
	var result map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	w = send(r, "/api/pair", "POST", "", nil, map[string]string{"code": result["code"]}, r.Origin)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	// A code is consumed by the first claimant, before local approval.
	again := send(r, "/api/pair", "POST", "", nil, map[string]string{"code": result["code"]}, r.Origin)
	if again.Code != 403 {
		t.Fatal("pairing code replay accepted")
	}
	return w.Result().Cookies()[0]
}
func TestPairingAuthorizationReplayAndIsolation(t *testing.T) {
	r := NewRelay("http://127.0.0.1:18765")
	a, b := strings.Repeat("a", 48), strings.Repeat("b", 48)
	browser := pair(t, r, a)
	other := pair(t, r, b)
	if w := send(r, "/api/plan", "POST", "", browser, map[string]string{"hostname": "access.example.com"}, r.Origin); w.Code != 409 {
		t.Fatal("browser controlled agent before local approval")
	}
	if w := send(r, "/agent/approve", "POST", a, nil, map[string]bool{"approve": true}, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := send(r, "/api/plan", "POST", "", browser, map[string]string{"hostname": "access.example.com"}, "http://attacker.test"); w.Code != 403 {
		t.Fatal("cross-origin request accepted")
	}
	w := send(r, "/api/plan", "POST", "", browser, map[string]string{"hostname": "access.example.com"}, r.Origin)
	var v View
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := send(r, "/api/run", "POST", "", other, map[string]string{"digest": v.Digest}, r.Origin); w.Code != 409 {
		t.Fatal("other session ran this plan")
	}
	if w := send(r, "/api/run", "POST", "", browser, map[string]string{"digest": "different"}, r.Origin); w.Code != 409 {
		t.Fatal("changed plan accepted")
	}
	if w := send(r, "/api/run", "POST", "", browser, map[string]string{"digest": v.Digest}, r.Origin); w.Code != 202 {
		t.Fatal(w.Code)
	}
	if w := send(r, "/api/run", "POST", "", browser, map[string]string{"digest": v.Digest}, r.Origin); w.Code != 409 {
		t.Fatal("duplicate run accepted")
	}
	w = send(r, "/agent/session", "GET", a, nil, nil, "")
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	id := v.Pending.ID
	for _, step := range []int{1, -2} {
		if send(r, "/agent/progress", "POST", a, nil, map[string]any{"id": id, "step": step}, "").Code < 400 {
			t.Fatal("invalid progress accepted")
		}
	}
	if send(r, "/agent/progress", "POST", a, nil, map[string]any{"id": id, "step": 0}, "").Code != 200 {
		t.Fatal("start rejected")
	}
	if send(r, "/agent/progress", "POST", a, nil, map[string]any{"id": id, "step": 0}, "").Code != 409 {
		t.Fatal("progress replay accepted")
	}
	if w := send(r, "/agent/progress", "POST", b, nil, map[string]any{"id": id, "step": 1}, ""); w.Code != 409 {
		t.Fatal("other agent advanced this command")
	}
	if w := send(r, "/api/session", "DELETE", "", browser, nil, r.Origin); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := send(r, "/agent/progress", "POST", a, nil, map[string]any{"id": id, "step": 1}, ""); w.Code != 409 {
		t.Fatal("revoked command executed")
	}
	if w := send(r, "/api/session", "GET", "", browser, nil, ""); w.Code != 401 {
		t.Fatal("revoked browser session remained usable")
	}
}
func TestInputLimitsAndExpiry(t *testing.T) {
	r := NewRelay("http://127.0.0.1:18765")
	for _, origin := range []string{"http://0.0.0.0:18765", "https://127.0.0.1:18765", "http://example.com:18765", "http://127.0.0.1:18765/path"} {
		if LocalOrigin(origin) {
			t.Fatal("nonlocal relay allowed")
		}
	}
	if _, _, err := plan("x;curl attacker.test"); err == nil {
		t.Fatal("invalid hostname accepted")
	}
	if w := send(r, "/agent/sessions", "POST", "", nil, map[string]string{"secret": strings.Repeat("a", 48), "shell": "whoami"}, ""); w.Code != 400 {
		t.Fatal("unknown action field accepted")
	}
	if w := send(r, "/api/pair", "POST", "", nil, map[string]string{"code": strings.Repeat("a", 5000)}, r.Origin); w.Code != 400 {
		t.Fatal("oversized request accepted")
	}
	for i := 0; i < 5; i++ {
		send(r, "/api/pair", "POST", "", nil, map[string]string{"code": "wrong"}, r.Origin)
	}
	if w := send(r, "/api/pair", "POST", "", nil, map[string]string{"code": "wrong"}, r.Origin); w.Code != 429 {
		t.Fatal("guessing not limited")
	}
	r.attemptWindow = time.Now().Add(-time.Minute)
	secret := strings.Repeat("a", 48)
	browser := pair(t, r, secret)
	r.sessions[0].expires = time.Now().Add(-time.Second)
	if w := send(r, "/api/session", "GET", "", browser, nil, ""); w.Code != 401 {
		t.Fatal("expired session accepted")
	}
}

func TestAgentSimulationEndToEnd(t *testing.T) {
	r := NewRelay("")
	server := httptest.NewServer(r)
	defer server.Close()
	r.Origin = server.URL
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunAgent(ctx, server.URL, strings.NewReader("PAIR\naccess.example.com\n"), io.Discard) }()
	var code string
	deadline := time.Now().Add(10 * time.Second)
	for code == "" && time.Now().Before(deadline) {
		r.mu.Lock()
		if len(r.sessions) > 0 {
			code = r.sessions[0].code
		}
		r.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	if code == "" {
		t.Fatal("agent did not create session")
	}
	w := send(r, "/api/pair", "POST", "", nil, map[string]string{"code": code}, r.Origin)
	if w.Code != 200 {
		t.Fatal("pair failed")
	}
	browser := w.Result().Cookies()[0]
	awaitStatus := func(expected string) {
		t.Helper()
		for time.Now().Before(deadline) {
			w := send(r, "/api/session", "GET", "", browser, nil, "")
			var v View
			_ = json.Unmarshal(w.Body.Bytes(), &v)
			if v.Status == expected {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("did not reach %s", expected)
	}
	awaitStatus("connected")
	w = send(r, "/api/plan", "POST", "", browser, map[string]string{"hostname": "access.example.com"}, r.Origin)
	var v View
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if w.Code != 200 {
		t.Fatal("plan failed")
	}
	if send(r, "/api/run", "POST", "", browser, map[string]string{"digest": v.Digest}, r.Origin).Code != 202 {
		t.Fatal("run failed")
	}
	awaitStatus("complete")
	send(r, "/api/session", "DELETE", "", browser, nil, r.Origin)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not stop after disconnect")
	}
}
