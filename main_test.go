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
	admin := strings.Repeat("b", 64)
	device := strings.Repeat("c", 32)
	access, err := openAccess(root)
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer((&server{root: root, adminKey: admin, access: access}).routes())
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
			req.Header.Set("X-Yap-Device", device)
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
	pair := fmt.Sprintf(`{"id":"%s","name":"Client","key":"%s"}`, device, secret)
	if status := request(http.MethodPost, "/v1/pair", pair, "", http.StatusOK); !strings.Contains(status, "pending") {
		t.Fatal("new device did not enter the pending list")
	}
	request(http.MethodGet, "/v1/devices", "", secret, http.StatusUnauthorized)
	request(http.MethodGet, "/v1/admin/devices", "", secret, http.StatusUnauthorized)
	request(http.MethodPut, "/v1/admin/devices/"+device, `{"status":"allowed"}`, admin, http.StatusNoContent)
	request(http.MethodGet, "/v1/devices", "", strings.Repeat("d", 64), http.StatusUnauthorized)
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
	other := strings.Repeat("e", 32)
	request(http.MethodPut, "/v1/devices/"+other, fmt.Sprintf(`{"version":1,"device":"%s"}`, other), secret, http.StatusForbidden)
	request(http.MethodPut, "/v1/admin/devices/"+device, `{"status":"blocked"}`, admin, http.StatusNoContent)
	request(http.MethodGet, endpoint, "", secret, http.StatusUnauthorized)
	if status := request(http.MethodPost, "/v1/pair", pair, "", http.StatusOK); !strings.Contains(status, "blocked") {
		t.Fatal("blocked device regained access by pairing again")
	}
	reopened, err := openAccess(root)
	if err != nil || reopened.allowed(device, secret) {
		t.Fatalf("blocked access did not survive reopening: %v", err)
	}
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
	if first.Admin != second.Admin || string(first.Cert) != string(second.Cert) {
		t.Fatal("server identity changed on restart")
	}
}

func TestDiscoveryOnlyAnswersYAPQueries(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	packet, ok := discoveryResponse([]byte(`{"protocol":"yap-sync-discovery/1","nonce":"`+nonce+`"}`),
		"Server", "yapsync2.test")
	if !ok || !strings.Contains(string(packet), nonce) {
		t.Fatal("matching query got no reply")
	}
	for _, malformed := range []string{`{}`, `{"protocol":"other","nonce":"` + nonce + `"}`,
		`{"protocol":"yap-sync-discovery/1","nonce":"short"}`} {
		if _, ok := discoveryResponse([]byte(malformed), "Server", "yapsync2.test"); ok {
			t.Fatalf("answered invalid request: %s", malformed)
		}
	}
}
