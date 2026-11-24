package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const pendingTTL = 15 * time.Minute

type credentials struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

func (c credentials) valid() bool {
	return validHex(c.ID, 32) && validHex(c.Key, 64) &&
		strings.TrimSpace(c.Name) != "" && len(c.Name) <= 120 &&
		strings.IndexFunc(c.Name, unicode.IsControl) == -1
}

type deviceAccess struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	KeyHash string `json:"keyHash,omitempty"`
	Code    string `json:"code"`
	Local   bool   `json:"local"`
	SeenAt  int64  `json:"seenAt"`
}

type accessList struct {
	mu   sync.Mutex
	path string
	byID map[string]deviceAccess
}

func openAccess(root string) (*accessList, error) {
	list := &accessList{path: filepath.Join(root, "access.json"), byID: map[string]deviceAccess{}}
	raw, err := os.ReadFile(list.path)
	if errors.Is(err, os.ErrNotExist) {
		return list, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &list.byID); err != nil || list.byID == nil || len(list.byID) > maxDevices {
		return nil, errors.New("invalid device access list")
	}
	return list, nil
}

func keyHash(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

func equalKey(first, second string) bool {
	return subtle.ConstantTimeCompare([]byte(first), []byte(second)) == 1
}

func (a *accessList) save(next map[string]deviceAccess) error {
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := writeAtomic(a.path, bytes.NewReader(data)); err != nil {
		return err
	}
	a.byID = next
	return nil
}

// Call with the lock held. Expired pairing requests never grant access.
func (a *accessList) active() map[string]deviceAccess {
	next := make(map[string]deviceAccess, len(a.byID))
	cutoff := time.Now().Add(-pendingTTL).Unix()
	for id, device := range a.byID {
		if device.Status != "pending" || device.SeenAt >= cutoff {
			next[id] = device
		}
	}
	return next
}

func (a *accessList) request(c credentials, local bool) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	hash := keyHash(c.Key)
	next := a.active()
	if existing, ok := next[c.ID]; ok && !local {
		if !equalKey(existing.KeyHash, hash) {
			return "blocked", nil
		}
		return existing.Status, nil
	}
	if _, existing := next[c.ID]; !existing && len(next) >= maxDevices {
		return "", errors.New("device access list is full")
	}
	device := deviceAccess{
		ID: c.ID, Name: c.Name, Status: "pending", KeyHash: hash,
		Code: strings.ToUpper(hash[:12]), SeenAt: time.Now().Unix(), Local: local,
	}
	if local {
		device.Status = "allowed"
	}
	next[c.ID] = device
	return device.Status, a.save(next)
}

func (a *accessList) allowed(id, key string) bool {
	if !validHex(id, 32) || !validHex(key, 64) {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	device, found := a.byID[id]
	return found && device.Status == "allowed" && equalKey(device.KeyHash, keyHash(key))
}

func (a *accessList) published(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.byID[id].Status == "allowed"
}

func (a *accessList) devices() []deviceAccess {
	a.mu.Lock()
	defer a.mu.Unlock()
	next := a.active()
	devices := make([]deviceAccess, 0, len(next))
	for _, device := range next {
		device.KeyHash = ""
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].ID < devices[j].ID
	})
	return devices
}

func (a *accessList) change(id, status string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	next := a.active()
	device, found := next[id]
	if !found || device.Local || (status != "allowed" && status != "blocked") {
		return errors.New("invalid device access change")
	}
	device.Status = status
	next[id] = device
	return a.save(next)
}

func (s *server) pair(w http.ResponseWriter, r *http.Request) {
	var client credentials
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil || json.Unmarshal(body, &client) != nil || !client.valid() {
		http.Error(w, "Invalid device credentials", http.StatusBadRequest)
		return
	}
	status, err := s.access.request(client, false)
	if err != nil {
		http.Error(w, "Cannot register device", http.StatusInsufficientStorage)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": status})
}

func (s *server) admin(w http.ResponseWriter, r *http.Request) {
	if !equalKey(r.Header.Get("Authorization"), "Bearer "+s.adminKey) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.access.devices())
		return
	}
	id := r.PathValue("id")
	var change struct {
		Status string `json:"status"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 512))
	if err != nil || !validHex(id, 32) || json.Unmarshal(body, &change) != nil || s.access.change(id, change.Status) != nil {
		http.Error(w, "Invalid access change", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
