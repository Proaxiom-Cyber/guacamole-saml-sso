// Manual-return experiment: hidden terminal input, no listener or callback service.
package main

import (
	"bytes"

	"crypto/rand"

	"crypto/sha256"
	"encoding/base64"

	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/term"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

func random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic("random source failed")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func call(method, target, token, content string, body []byte) (int, map[string]json.RawMessage, error) {
	req, e := http.NewRequest(method, target, bytes.NewReader(body))
	if e != nil {
		return 0, nil, errors.New("request construction failed")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if content != "" {
		req.Header.Set("Content-Type", content)
	}
	r, e := httpClient.Do(req)
	if e != nil {
		return 0, nil, errors.New("HTTPS request failed")
	}
	defer r.Body.Close()
	var d map[string]json.RawMessage
	_ = json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&d)
	return r.StatusCode, d, nil
}
func str(d map[string]json.RawMessage, k string) string {
	var s string
	_ = json.Unmarshal(d[k], &s)
	return s
}
func require(ok bool, msg string) {
	if !ok {
		panic(msg)
	}
}
func main() {
	defer func() {
		if recover() != nil {
			fmt.Println("FAILED: test stopped; no credentials were printed.")
			os.Exit(1)
		}
	}()
	clientID := flag.String("client-id", "", "Registered client identifier")
	publicLink := flag.String("link-file", "", "Public authorization URL output")
	report := flag.String("report", "", "Non-secret completion report")
	flag.Parse()
	success := false
	var results strings.Builder
	defer func() {
		if *report != "" {
			result := "FAILED"
			if success {
				result = "PASS"
			}
			_ = os.WriteFile(*report, []byte(results.String()+result+"\n"), 0600)
		}
	}()
	verifier, state := random(), random()
	challenge := sha256.Sum256([]byte(verifier))
	redirect := "http://localhost:18977/callback"
	auth := url.Values{"client_id": {*clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "response_mode": {"query"}, "scope": {"argotunnel.write access.write access-acct.write dns.write zone.read offline_access"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}}
	address := "https://dash.cloudflare.com/oauth2/auth?" + auth.Encode()
	if *publicLink != "" {
		require(os.WriteFile(*publicLink, []byte(address), 0600) == nil, "cannot write public link")
	}
	fmt.Println("CLOUDFLARE MANUAL RETURN TEST")
	fmt.Println("Approve the test in the browser. It will then show a localhost connection error.")
	fmt.Println("Copy the FULL address from the browser address bar and paste it below.")
	fmt.Println("The paste is hidden. Do not paste the address into chat or a shell command.")
	fmt.Println("No callback service or listening port is running.")
	var code string
	for {
		fmt.Print("\nPaste returned address, then press Enter (hidden): ")
		input, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		require(err == nil, "hidden input failed")
		returned, err := url.Parse(strings.TrimSpace(string(input)))
		if err != nil || returned.Scheme != "http" || returned.Host != "localhost:18977" || returned.Path != "/callback" || returned.User != nil || returned.Fragment != "" {
			fmt.Println("That is not the expected localhost address. Try again.")
			continue
		}
		q, err := url.ParseQuery(returned.RawQuery)
		if err != nil || len(q["state"]) != 1 || q.Get("state") != state {
			fmt.Println("That address belongs to a different sign-in attempt. Use the current browser link.")
			continue
		}
		require(q.Get("error") == "", "authorization denied")
		if len(q["code"]) != 1 || q.Get("code") == "" {
			fmt.Println("The address has no authorization code. Try again.")
			continue
		}
		code = q.Get("code")
		break
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {*clientID}, "redirect_uri": {redirect}, "code": {code}, "code_verifier": {verifier}}
	status, tokens, e := call("POST", "https://dash.cloudflare.com/oauth2/token", "", "application/x-www-form-urlencoded", []byte(form.Encode()))
	fmt.Printf("Code exchange HTTP %d\n", status)
	fmt.Fprintf(&results, "Code exchange HTTP %d\n", status)
	require(e == nil && status == 200, "token exchange failed")
	access, refresh := str(tokens, "access_token"), str(tokens, "refresh_token")
	require(access != "", "access token missing")
	allAccess := []string{access}
	allRefresh := []string{refresh}
	defer func() {
		for _, group := range []struct {
			hint   string
			values []string
		}{{"refresh_token", allRefresh}, {"access_token", allAccess}} {
			for _, token := range group.values {
				if token == "" {
					continue
				}
				f := url.Values{"client_id": {*clientID}, "token": {token}, "token_type_hint": {group.hint}}
				status, _, _ := call("POST", "https://dash.cloudflare.com/oauth2/revoke", "", "application/x-www-form-urlencoded", []byte(f.Encode()))
				fmt.Printf("Revoke %s HTTP %d\n", group.hint, status)
				fmt.Fprintf(&results, "Revoke %s HTTP %d\n", group.hint, status)
				if status != 200 {
					success = false
				}
			}
		}
	}()
	fmt.Printf("Token lifetime seconds: %s; refresh present: %t\n", string(tokens["expires_in"]), refresh != "")
	base := "https://api.cloudflare.com/client/v4"
	account := "7c3fbcc2ed71191b09eed3e3a827ea4c"
	zone := "bd33a2e2c0b9cdb67ca10cfdbed00a00"
	for _, test := range []struct{ label, path string }{{"account selection", "/accounts?per_page=1"}, {"zone", "/zones/" + zone}, {"DNS", "/zones/" + zone + "/dns_records?per_page=1"}, {"Tunnel", "/accounts/" + account + "/cfd_tunnel?per_page=1&is_deleted=false"}, {"Access apps", "/accounts/" + account + "/access/apps?per_page=1"}, {"Access identity providers", "/accounts/" + account + "/access/identity_providers?per_page=1"}, {"Access organization", "/accounts/" + account + "/access/organizations"}} {
		status, d, e := call("GET", base+test.path, access, "", nil)
		fmt.Printf("Read %s HTTP %d\n", test.label, status)
		fmt.Fprintf(&results, "Read %s HTTP %d; success %t\n", test.label, status, string(d["success"]) == "true")
		require(e == nil && status == 200 && string(d["success"]) == "true", "resource read failed")
	}
	if refresh != "" {
		f := url.Values{"grant_type": {"refresh_token"}, "client_id": {*clientID}, "refresh_token": {refresh}}
		status, d, e := call("POST", "https://dash.cloudflare.com/oauth2/token", "", "application/x-www-form-urlencoded", []byte(f.Encode()))
		fmt.Printf("Refresh HTTP %d\n", status)
		fmt.Fprintf(&results, "Refresh HTTP %d\n", status)
		require(e == nil && status == 200 && str(d, "access_token") != "", "refresh failed")
		allAccess = append(allAccess, str(d, "access_token"))
		if r := str(d, "refresh_token"); r != "" {
			allRefresh = append(allRefresh, r)
		}
	}
	success = true
	fmt.Println("PASS: manual return, state validation, direct code exchange, seven API reads, and refresh")
}
