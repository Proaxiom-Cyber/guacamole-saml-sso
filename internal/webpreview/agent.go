package webpreview

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func LocalOrigin(origin string) bool {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback() && u.Port() != ""
}

// RunAgent has no listener and executes only a built-in simulation.
func RunAgent(ctx context.Context, origin string, in io.Reader, out io.Writer) error {
	if !LocalOrigin(origin) {
		return errors.New("this unauthenticated prototype only supports a loopback relay")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	h := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	secret := nonce()
	call := func(ctx context.Context, method, path string, body any, result any) error {
		data, _ := json.Marshal(body)
		req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(origin, "/")+path, bytes.NewReader(data))
		if e != nil {
			return errors.New("request failed")
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Content-Type", "application/json")
		res, e := h.Do(req)
		if e != nil {
			return errors.New("relay connection lost; remote preview stopped")
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return errors.New("relay rejected the action; preview stopped")
		}
		if result != nil && json.NewDecoder(io.LimitReader(res.Body, 16384)).Decode(result) != nil {
			return errors.New("invalid relay response")
		}
		return nil
	}
	var start struct {
		Code string `json:"code"`
	}
	if e := call(ctx, "POST", "/agent/sessions", map[string]string{"secret": secret}, &start); e != nil {
		return e
	}
	defer func() {
		clean, done := context.WithTimeout(context.Background(), 2*time.Second)
		defer done()
		_ = call(clean, "DELETE", "/agent/session", nil, nil)
	}()
	fmt.Fprintf(out, "\nPROAXIOM / BROWSER CONTROL PREVIEW\n\nSimulation only. No cloud resources or server settings will change.\nAdministrator sign-in is not implemented; this preview is local only.\n\nOpen %s on this computer.\nPairing code: %s\n\nWaiting for the browser. Press Ctrl+C to disconnect.\n", origin, start.Code)
	reader := bufio.NewReader(in)
	approve := func(message, expected string) bool {
		fmt.Fprintln(out, "\n"+message)
		fmt.Fprintf(out, "Type %s to approve, or anything else to decline: ", expected)
		result := make(chan string, 1)
		go func() { line, _ := reader.ReadString('\n'); result <- strings.TrimSpace(line) }()
		select {
		case <-ctx.Done():
			return false
		case line := <-result:
			return line == expected
		}
	}
	seen := map[string]bool{}
	paired := false
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		var v View
		if e := call(ctx, "GET", "/agent/session", nil, &v); e != nil {
			return e
		}
		if v.Status == "ended" {
			fmt.Fprintln(out, "Browser disconnected. Preview ended.")
			return nil
		}
		if v.Status == "pairing" && !paired {
			ok := approve("A local preview browser requested control. No administrator identity has been verified.", "PAIR")
			if e := call(ctx, "POST", "/agent/approve", map[string]bool{"approve": ok}, nil); e != nil {
				return e
			}
			if !ok {
				return nil
			}
			paired = true
			fmt.Fprintln(out, "Browser paired. Only simulation requests are allowed.")
		}
		if v.Pending == nil {
			continue
		}
		c := v.Pending
		if !paired || seen[c.ID] {
			return errors.New("unauthorized or repeated command rejected locally")
		}
		digest, steps, e := plan(c.Hostname)
		if e != nil || c.Kind != "simulate-setup" || c.Digest != digest || len(c.ID) != 48 {
			return errors.New("unknown or changed command rejected locally")
		}
		seen[c.ID] = true
		ok := approve("The browser requests a SIMULATED setup for "+c.Hostname+". No deployment resources will change.", c.Hostname)
		progress := func(step int) error {
			return call(ctx, "POST", "/agent/progress", map[string]any{"id": c.ID, "step": step}, nil)
		}
		if !ok {
			if e := progress(-1); e != nil {
				return e
			}
			continue
		}
		if e := progress(0); e != nil {
			return e
		}
		for i, step := range steps {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(700 * time.Millisecond):
			}
			if e := progress(i + 1); e != nil {
				return e
			}
			fmt.Fprintln(out, "  "+step+" — simulated")
		}
		fmt.Fprintln(out, "Preview complete. The browser can prepare another plan or disconnect.")
	}
}
