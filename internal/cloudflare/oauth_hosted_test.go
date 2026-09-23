package cloudflare

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHostedOAuthBindsCodeAndCleansSession(t *testing.T) {
	id := strings.Repeat("a", 64)
	var public *rsa.PublicKey
	var challenge, hash, poll string
	polls, deletes := 0, 0
	config := OAuthConfig{ClientID: "fixture", RelayURL: "https://relay.example.test", PollInterval: time.Millisecond}
	config.HTTP = &http.Client{Transport: oauthTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "relay.example.test" {
			switch r.Method + " " + r.URL.Path {
			case "POST /sessions":
				var input struct {
					Challenge string `json:"challenge"`
					Hash      string `json:"poll_hash"`
					Public    struct {
						N string `json:"n"`
					} `json:"public_key"`
				}
				if json.NewDecoder(r.Body).Decode(&input) != nil {
					t.Fatal("invalid session")
				}
				n, _ := base64.RawURLEncoding.DecodeString(input.Public.N)
				public = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}
				challenge, hash = input.Challenge, input.Hash
				res := oauthResponse(`{"id":"` + id + `","client_id":"fixture"}`)
				res.StatusCode = 201
				return res, nil
			case "GET /poll/" + id:
				poll = r.Header.Get("Authorization")
				if !strings.HasPrefix(poll, "Bearer ") {
					t.Fatal("missing polling credential")
				}
				sum := sha256.Sum256([]byte(strings.TrimPrefix(poll, "Bearer ")))
				if hash != hex.EncodeToString(sum[:]) {
					t.Fatal("poll hash mismatch")
				}
				polls++
				if polls == 1 {
					res := oauthResponse(`{}`)
					res.StatusCode = 503
					return res, nil
				}
				key := make([]byte, 32)
				_, _ = rand.Read(key)
				block, _ := aes.NewCipher(key)
				gcm, _ := cipher.NewGCM(block)
				iv := make([]byte, 12)
				_, _ = rand.Read(iv)
				data := gcm.Seal(nil, iv, []byte(`{"code":"fixture-code"}`), nil)
				wrapped, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, public, key, nil)
				b, _ := json.Marshal(oauthEnvelope{Key: base64.StdEncoding.EncodeToString(wrapped), IV: base64.StdEncoding.EncodeToString(iv), Data: base64.StdEncoding.EncodeToString(data)})
				return oauthResponse(string(b)), nil
			case "DELETE /poll/" + id:
				deletes++
				if r.Header.Get("Authorization") != poll {
					t.Fatal("cleanup credentials changed")
				}
				return oauthResponse(`{}`), nil
			}
		}
		if r.URL.String() == tokenURL {
			b, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(b))
			sum := sha256.Sum256([]byte(form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || form.Get("code") != "fixture-code" || form.Get("redirect_uri") != config.RelayURL+"/callback" {
				t.Fatal("code exchange not bound to hosted session")
			}
			if r.Header.Get("Authorization") != "" {
				t.Fatal("polling credential sent to token endpoint")
			}
			return oauthResponse(`{"access_token":"a","refresh_token":"r","token_type":"bearer","expires_in":3600}`), nil
		}
		t.Fatal("unexpected request")
		return nil, nil
	})}
	value, err := config.AuthorizeHosted(context.Background(), func(link string) error {
		if link != config.RelayURL+"/start/"+id {
			t.Fatal("incorrect link")
		}
		return nil
	})
	if err != nil || !IsOAuthCredential(value) || deletes != 1 || polls != 2 {
		t.Fatalf("hosted flow failed: %v", err)
	}
}

func TestHostedValidationAndMalformedEnvelope(t *testing.T) {
	for _, origin := range []string{"http://relay.test", "https://user@relay.test", "https://relay.test/path", "https://relay.test?token=x", "https://relay.test#x"} {
		if (OAuthConfig{ClientID: "fixture", RelayURL: origin}).ValidateHosted() == nil {
			t.Fatal("accepted unsafe relay origin")
		}
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := (oauthEnvelope{Key: "invalid"}).code(key); err == nil {
		t.Fatal("accepted malformed envelope")
	}
}
