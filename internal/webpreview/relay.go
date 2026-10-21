// Package webpreview is a loopback-only interaction prototype. It cannot deploy,
// run shell commands, read credentials, or provide remote administrator identity.
package webpreview

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed static/*
var assets embed.FS

type Command struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Hostname string `json:"hostname"`
	Digest   string `json:"digest"`
}
type View struct {
	Status   string   `json:"status"`
	Hostname string   `json:"hostname"`
	Digest   string   `json:"digest"`
	Steps    []string `json:"steps"`
	Events   []string `json:"events"`
	Pending  *Command `json:"pending,omitempty"`
}
type session struct {
	agent, browser [32]byte
	code           string
	expires        time.Time
	view           View
	issued         map[string]bool
	nextStep       int
}
type Relay struct {
	mu            sync.Mutex
	Origin        string
	sessions      []*session
	attempts      int
	attemptWindow time.Time
}

func NewRelay(origin string) *Relay { return &Relay{Origin: origin} }
func nonce() string                 { b := make([]byte, 24); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func fingerprint(v string) [32]byte { return sha256.Sum256([]byte(v)) }
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		reply(w, 400, map[string]string{"error": "Invalid request"})
		return false
	}
	return true
}
func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}

var hostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func plan(host string) (string, []string, error) {
	if len(host) > 253 || !hostPattern.MatchString(host) {
		return "", nil, errors.New("Enter a full hostname, such as access.example.com")
	}
	steps := []string{"Check deployment settings", "Connect Cloudflare", "Configure the deployment", "Verify protected access", "Complete setup"}
	sum := sha256.Sum256([]byte("preview-v1\x00" + host))
	return hex.EncodeToString(sum[:]), steps, nil
}
func (r *Relay) ServeHTTP(w http.ResponseWriter, q *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	// The prototype is local only. Host validation also blocks DNS rebinding.
	if "http://"+q.Host != r.Origin {
		fail(w, 403, "Unexpected host")
		return
	}
	if strings.HasPrefix(q.URL.Path, "/api/") && q.Method != "GET" && q.Header.Get("Origin") != r.Origin {
		fail(w, 403, "Unexpected browser origin")
		return
	}
	if q.Method == "GET" && (q.URL.Path == "/" || q.URL.Path == "/app.js" || q.URL.Path == "/style.css") {
		file := q.URL.Path
		if file == "/" {
			file = "/index.html"
		}
		b, _ := assets.ReadFile("static" + file)
		content := "text/html; charset=utf-8"
		if file == "/app.js" {
			content = "application/javascript"
		}
		if file == "/style.css" {
			content = "text/css"
		}
		w.Header().Set("Content-Type", content)
		_, _ = w.Write(b)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	alive := r.sessions[:0]
	for _, s := range r.sessions {
		if now.Before(s.expires) {
			alive = append(alive, s)
		}
	}
	r.sessions = alive
	if q.URL.Path == "/agent/sessions" && q.Method == "POST" {
		if len(r.sessions) >= 20 {
			fail(w, 429, "Preview session limit reached")
			return
		}
		var input struct {
			Secret string `json:"secret"`
		}
		if !decode(w, q, &input) {
			return
		}
		if len(input.Secret) != 48 {
			fail(w, 400, "Invalid session credential")
			return
		}
		b := make([]byte, 5)
		_, _ = rand.Read(b)
		code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
		code = code[:4] + "-" + code[4:]
		s := &session{agent: fingerprint(input.Secret), code: code, expires: now.Add(5 * time.Minute), view: View{Status: "waiting", Events: []string{}}, issued: map[string]bool{}}
		r.sessions = append(r.sessions, s)
		reply(w, 201, map[string]string{"code": code})
		return
	}
	if q.URL.Path == "/api/pair" && q.Method == "POST" {
		if now.Sub(r.attemptWindow) > time.Minute {
			r.attemptWindow = now
			r.attempts = 0
		}
		r.attempts++
		if r.attempts > 5 {
			fail(w, 429, "Too many attempts. Wait one minute.")
			return
		}
		var input struct {
			Code string `json:"code"`
		}
		if !decode(w, q, &input) {
			return
		}
		for _, s := range r.sessions {
			if s.code != "" && strings.EqualFold(strings.TrimSpace(input.Code), s.code) && s.view.Status == "waiting" {
				token := nonce()
				s.browser = fingerprint(token)
				s.code = ""
				s.view.Status = "pairing"
				s.view.Events = append(s.view.Events, "Browser requested pairing. Waiting for terminal confirmation.")
				http.SetCookie(w, &http.Cookie{Name: "preview-session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 1800})
				reply(w, 200, s.view)
				return
			}
		}
		fail(w, 403, "Code expired, already used, or incorrect")
		return
	}
	var s *session
	agent := strings.HasPrefix(q.URL.Path, "/agent/")
	token := ""
	if agent {
		token = strings.TrimPrefix(q.Header.Get("Authorization"), "Bearer ")
	} else {
		if c, e := q.Cookie("preview-session"); e == nil {
			token = c.Value
		}
	}
	if token != "" {
		fp := fingerprint(token)
		for _, candidate := range r.sessions {
			if (agent && candidate.agent == fp) || (!agent && candidate.browser == fp) {
				s = candidate
				break
			}
		}
	}
	if s == nil {
		fail(w, 401, "Session unavailable. Start a new pairing from the terminal.")
		return
	}
	if q.Method == "DELETE" && (q.URL.Path == "/api/session" || q.URL.Path == "/agent/session") {
		s.view.Status = "ended"
		s.view.Pending = nil
		s.browser = [32]byte{}
		s.expires = now.Add(time.Minute)
		reply(w, 200, map[string]bool{"ended": true})
		return
	}
	if q.Method == "GET" && (q.URL.Path == "/api/session" || q.URL.Path == "/agent/session") {
		v := s.view
		if !agent {
			v.Pending = nil
		}
		reply(w, 200, v)
		return
	}
	if agent && q.Method == "POST" && q.URL.Path == "/agent/approve" {
		if s.view.Status != "pairing" {
			fail(w, 409, "Pairing is not pending")
			return
		}
		var input struct {
			Approve bool `json:"approve"`
		}
		if !decode(w, q, &input) {
			return
		}
		if !input.Approve {
			s.view.Status = "ended"
			s.browser = [32]byte{}
		} else {
			s.view.Status = "connected"
			s.expires = now.Add(30 * time.Minute)
			s.view.Events = append(s.view.Events, "Terminal approved this preview session.")
		}
		reply(w, 200, s.view)
		return
	}
	if !agent && q.Method == "POST" && q.URL.Path == "/api/plan" {
		if s.view.Status != "connected" && s.view.Status != "planned" && s.view.Status != "complete" {
			fail(w, 409, "The terminal is not ready for a new plan")
			return
		}
		var input struct {
			Hostname string `json:"hostname"`
		}
		if !decode(w, q, &input) {
			return
		}
		host := strings.ToLower(strings.TrimSpace(input.Hostname))
		digest, steps, err := plan(host)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		s.view.Hostname = host
		s.view.Digest = digest
		s.view.Steps = steps
		s.view.Status = "planned"
		reply(w, 200, s.view)
		return
	}
	if !agent && q.Method == "POST" && q.URL.Path == "/api/run" {
		if s.view.Status != "planned" {
			fail(w, 409, "This plan is not available to run")
			return
		}
		var input struct {
			Digest string `json:"digest"`
		}
		if !decode(w, q, &input) {
			return
		}
		if input.Digest != s.view.Digest {
			fail(w, 409, "The plan changed. Review it again.")
			return
		}
		cmd := &Command{ID: nonce(), Kind: "simulate-setup", Hostname: s.view.Hostname, Digest: s.view.Digest}
		s.nextStep = 0
		s.view.Pending = cmd
		s.issued[cmd.ID] = true
		s.view.Status = "approval"
		s.view.Events = append(s.view.Events, "Preview requested. Confirm this exact hostname in the terminal.")
		reply(w, 202, s.view)
		return
	}
	if agent && q.Method == "POST" && q.URL.Path == "/agent/progress" {
		var input struct {
			ID   string `json:"id"`
			Step int    `json:"step"`
		}
		if !decode(w, q, &input) {
			return
		}
		if s.view.Pending == nil || s.view.Pending.ID != input.ID || !s.issued[input.ID] || (s.view.Status != "approval" && s.view.Status != "running") {
			fail(w, 409, "Command is no longer active")
			return
		}
		if input.Step == -1 && s.nextStep == 0 {
			delete(s.issued, input.ID)
			s.view.Pending = nil
			s.view.Status = "connected"
			s.view.Events = append(s.view.Events, "Terminal declined the preview.")
			reply(w, 200, s.view)
			return
		}
		if input.Step < 0 || input.Step > len(s.view.Steps) {
			fail(w, 400, "Invalid step")
			return
		}
		if input.Step != s.nextStep {
			fail(w, 409, "Repeated or out-of-order step")
			return
		}
		s.nextStep++
		s.view.Status = "running"
		if input.Step > 0 {
			s.view.Events = append(s.view.Events, s.view.Steps[input.Step-1]+" — simulated")
		}
		if input.Step == len(s.view.Steps) {
			s.view.Status = "complete"
			delete(s.issued, input.ID)
			s.view.Pending = nil
			s.view.Events = append(s.view.Events, "Preview complete. No deployment resources were changed.")
		}
		if len(s.view.Events) > 40 {
			s.view.Events = s.view.Events[len(s.view.Events)-40:]
		}
		reply(w, 200, s.view)
		return
	}
	fail(w, 404, "Action unavailable")
}
