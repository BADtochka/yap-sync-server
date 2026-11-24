package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrackStorageRequiresAuthorizationAndVerifiesContent(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"tracks", "devices", "repairs"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	secret := strings.Repeat("a", 64)
	service := httptest.NewServer((&server{root: root, secret: secret}).routes())
	defer service.Close()

	track := "track contents"
	hash := sha256.Sum256([]byte(track))
	digest := hex.EncodeToString(hash[:])
	endpoint := "/v1/tracks/" + digest
	request := func(method, path, body, token string, want int) string {
		t.Helper()
		req, err := http.NewRequest(method, service.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := service.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("%s %s: got %d, want %d", method, path, res.StatusCode, want)
		}
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	request(http.MethodPut, endpoint, track, "", http.StatusUnauthorized)
	request(http.MethodPut, endpoint, "different bytes", secret, http.StatusUnprocessableEntity)
	request(http.MethodGet, endpoint, "", secret, http.StatusNotFound)
	request(http.MethodPut, endpoint, track, secret, http.StatusNoContent)
	if got := request(http.MethodGet, endpoint, "", secret, http.StatusOK); got != track {
		t.Fatalf("received wrong track: %q", got)
	}
	request(http.MethodPut, "/v1/tracks/%2e%2e", track, secret, http.StatusBadRequest)
	batch := fmt.Sprintf(`[{"digest":"%s","bytes":%d}]`, digest, len(track))
	if present := request(http.MethodPost, "/v1/tracks/present", batch, secret, http.StatusOK); !strings.Contains(present, digest) {
		t.Fatal("existing track absent from batch response")
	}
	request(http.MethodPost, endpoint+"/repair", "", secret, http.StatusNoContent)
	if present := request(http.MethodPost, "/v1/tracks/present", batch, secret, http.StatusOK); strings.Contains(present, digest) {
		t.Fatal("corrupt track included in batch response")
	}
	request(http.MethodGet, "/v1/devices", "", "", http.StatusUnauthorized)
}

func TestInvitationIdentitySurvivesRestartOnSameAddress(t *testing.T) {
	root := t.TempDir()
	ip := netip.MustParseAddr("127.0.0.1")
	first, err := loadIdentity(root, ip)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadIdentity(root, ip)
	if err != nil {
		t.Fatal(err)
	}
	if first.Secret != second.Secret || string(first.Cert) != string(second.Cert) {
		t.Fatal("server identity changed on restart")
	}
}
