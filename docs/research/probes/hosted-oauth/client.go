// Standalone experiment: outbound HTTPS only, no listener or browser launch.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
func unseal(priv *rsa.PrivateKey, d map[string]json.RawMessage) map[string]json.RawMessage {
	decode := func(k string) []byte {
		b, e := base64.StdEncoding.DecodeString(str(d, k))
		require(e == nil, "invalid encrypted response")
		return b
	}
	key, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, decode("key"), nil)
	require(e == nil, "cannot decrypt envelope key")
	block, e := aes.NewCipher(key)
	require(e == nil, "invalid envelope key")
	gcm, e := cipher.NewGCM(block)
	require(e == nil, "cipher failed")
	data, e := gcm.Open(nil, decode("iv"), decode("data"), nil)
	require(e == nil, "cannot decrypt authorization response")
	var result map[string]json.RawMessage
	require(json.Unmarshal(data, &result) == nil, "invalid authorization response")
	return result
}
func main() {
	defer func() {
		if recover() != nil {
			fmt.Println("FAILED: test stopped; no credentials were printed.")
			os.Exit(1)
		}
	}()
	origin := flag.String("relay", "", "Hosted callback origin")
	clientID := flag.String("client-id", "", "Registered public-client identifier")
	selftest := flag.Bool("selftest", false, "Check relay isolation using non-secret test data")
	flag.Parse()
	require(strings.HasPrefix(*origin, "https://"), "HTTPS relay required")
	priv, e := rsa.GenerateKey(rand.Reader, 2048)
	require(e == nil, "key generation failed")
	verifier, pollToken := random(), random()
	challenge := sha256.Sum256([]byte(verifier))
	pollHash := sha256.Sum256([]byte(pollToken))
	body, _ := json.Marshal(map[string]any{"challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "poll_hash": hex.EncodeToString(pollHash[:]), "public_key": map[string]string{"kty": "RSA", "n": base64.RawURLEncoding.EncodeToString(priv.N.Bytes()), "e": "AQAB"}})
	status, session, e := call("POST", *origin+"/sessions", "", "application/json", body)
	require(e == nil && status == 201, "session creation failed")
	id := str(session, "id")
	pollURL := *origin + "/poll/" + id
	status, _, e = call("GET", pollURL, random(), "", nil)
	require(e == nil && status == 403, "wrong polling credential was not rejected")
	fmt.Println("PASS: wrong polling credential rejected")
	status, _, e = call("GET", pollURL, pollToken, "", nil)
	require(e == nil && status == 202, "pending state failed")
	if *selftest {
		status, _, e = call("POST", *origin+"/callback", "", "application/x-www-form-urlencoded", []byte("state=invalid&code=nonsecret-test"))
		require(e == nil && status == 400, "invalid state not rejected")
		form := url.Values{"state": {id}, "code": {"nonsecret-relay-selftest"}}.Encode()
		status, _, e = call("POST", *origin+"/callback", "", "application/x-www-form-urlencoded", []byte(form))
		require(e == nil && status == 200, "test callback failed")
		status, _, e = call("POST", *origin+"/callback", "", "application/x-www-form-urlencoded", []byte(form))
		require(e == nil && status == 409, "duplicate callback not rejected")
		status, data, e := call("GET", pollURL, pollToken, "", nil)
		require(e == nil && status == 200, "encrypted result missing")
		require(str(unseal(priv, data), "code") == "nonsecret-relay-selftest", "relay encryption mismatch")
		status, _, e = call("GET", pollURL, pollToken, "", nil)
		require(e == nil && status == 410, "result was not consumed")
		fmt.Println("PASS: pending response, invalid state, duplicate callback, encrypted delivery, and single consumption")
		return
	}
	fmt.Println("Approve this test in a browser on another device:")
	fmt.Println(str(session, "authorization_url"))
	fmt.Println("Waiting up to 10 minutes. This process has no listening port.")
	var code string
	for deadline := time.Now().Add(10 * time.Minute); time.Now().Before(deadline); {
		time.Sleep(3 * time.Second)
		status, data, e := call("GET", pollURL, pollToken, "", nil)
		require(e == nil, "poll failed")
		if status == 202 {
			continue
		}
		require(status == 200, "session failed or expired")
		code = str(unseal(priv, data), "code")
		require(code != "", "authorization denied")
		break
	}
	require(code != "", "authorization timed out")
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {*clientID}, "redirect_uri": {*origin + "/callback"}, "code": {code}, "code_verifier": {verifier}}
	status, tokens, e := call("POST", "https://dash.cloudflare.com/oauth2/token", "", "application/x-www-form-urlencoded", []byte(form.Encode()))
	fmt.Printf("Code exchange HTTP %d\n", status)
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
			}
		}
	}()
	fmt.Printf("Token lifetime seconds: %s; refresh present: %t\n", string(tokens["expires_in"]), refresh != "")
	base := "https://api.cloudflare.com/client/v4"
	account := "7c3fbcc2ed71191b09eed3e3a827ea4c"
	zone := "bd33a2e2c0b9cdb67ca10cfdbed00a00"
	for _, test := range []struct{ label, path string }{{"account selection", "/accounts?per_page=1"}, {"zone", "/zones/" + zone}, {"DNS", "/zones/" + zone + "/dns_records?per_page=1"}, {"Tunnel", "/accounts/" + account + "/cfd_tunnel?per_page=1&is_deleted=false"}, {"Access apps", "/accounts/" + account + "/access/apps?per_page=1"}, {"Access identity providers", "/accounts/" + account + "/access/identity_providers?per_page=1"}, {"Access organization", "/accounts/" + account + "/access/organizations"}} {
		status, d, e := call("GET", base+test.path, access, "", nil)
		fmt.Printf("Read %s HTTP %d; success %s\n", test.label, status, string(d["success"]))
		require(e == nil && status == 200 && string(d["success"]) == "true", "resource read failed")
	}
	if refresh != "" {
		f := url.Values{"grant_type": {"refresh_token"}, "client_id": {*clientID}, "refresh_token": {refresh}}
		status, d, e := call("POST", "https://dash.cloudflare.com/oauth2/token", "", "application/x-www-form-urlencoded", []byte(f.Encode()))
		fmt.Printf("Refresh HTTP %d\n", status)
		require(e == nil && status == 200 && str(d, "access_token") != "", "refresh failed")
		allAccess = append(allAccess, str(d, "access_token"))
		if r := str(d, "refresh_token"); r != "" {
			allRefresh = append(allRefresh, r)
		}
	}
	status, _, e = call("GET", pollURL, pollToken, "", nil)
	require(e == nil && status == 410, "authorization code was replayable")
	fmt.Println("PASS: hosted callback, outbound-only Go client, API reads, refresh, and one-time code delivery")
}
