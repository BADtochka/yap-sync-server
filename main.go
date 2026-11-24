package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	protocolVersion = 1
	maxManifest     = 64 << 20
	maxTrack        = 2 << 30
	maxDevices      = 128
	maxTrackBatch   = 512
)

type identity struct {
	Address string `json:"address"`
	Secret  string `json:"secret"`
	Cert    []byte `json:"certificate"`
	Key     []byte `json:"key"`
}

type invitation struct {
	Address string `json:"address"`
	Secret  string `json:"secret"`
	Cert    []byte `json:"certificate"`
}

type server struct {
	root   string
	secret string
	mu     sync.Mutex // Device registration and publication share the same limit.
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:38737", "LAN IP address and port")
	data := flag.String("data", "", "private server storage directory")
	version := flag.Bool("version", false, "print server and protocol version")
	flag.Parse()
	if *version {
		fmt.Println("yap-sync-server 1")
		return nil
	}
	address, err := netip.ParseAddrPort(*listen)
	if err != nil || !privateIP(address.Addr()) || *data == "" {
		return errors.New("specify a private LAN or loopback IP address and a data directory")
	}
	if err := os.MkdirAll(*data, 0700); err != nil {
		return err
	}
	for _, dir := range []string{"devices", "tracks", "repairs"} {
		path := filepath.Join(*data, dir)
		if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("invalid storage directory %s", dir)
		}
	}
	id, err := loadIdentity(*data, address.Addr())
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(id.Cert, id.Key)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address.String())
	if err != nil {
		return err
	}
	defer listener.Close()

	dataForClient, err := json.Marshal(invitation{listener.Addr().String(), id.Secret, id.Cert})
	if err != nil {
		return err
	}
	fmt.Println("yapsync1." + base64.RawURLEncoding.EncodeToString(dataForClient))
	s := &server{root: *data, secret: id.Secret}
	httpServer := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Minute,
		WriteTimeout:      30 * time.Minute,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
		},
	}
	return httpServer.ServeTLS(listener, "", "")
}

func privateIP(ip netip.Addr) bool {
	return ip.IsValid() && ip.Zone() == "" && (ip.IsPrivate() || ip.IsLoopback())
}

func loadIdentity(root string, ip netip.Addr) (identity, error) {
	path := filepath.Join(root, "identity.json")
	var id identity
	raw, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(raw, &id); err != nil || !validHex(id.Secret, 64) {
			return identity{}, errors.New("invalid server identity file")
		}
		if id.Address == ip.String() {
			return id, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return identity{}, err
	}
	secret := make([]byte, 32)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return identity{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return identity{}, err
	}
	if _, err := rand.Read(secret); err != nil {
		return identity{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "YAP Sync"},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		IPAddresses:  []net.IP{net.IP(ip.AsSlice())},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return identity{}, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return identity{}, err
	}
	id = identity{
		Address: ip.String(),
		Secret:  hex.EncodeToString(secret),
		Cert:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Key:     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
	}
	raw, err = json.Marshal(id)
	if err != nil {
		return identity{}, err
	}
	return id, writeAtomic(path, bytes.NewReader(raw))
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":1}`)
	})
	mux.HandleFunc("GET /v1/devices", s.listDevices)
	mux.HandleFunc("GET /v1/devices/{device}", s.device)
	mux.HandleFunc("PUT /v1/devices/{device}", s.device)
	mux.HandleFunc("POST /v1/tracks/present", s.presentTracks)
	mux.HandleFunc("GET /v1/tracks/{digest}", s.track)
	mux.HandleFunc("PUT /v1/tracks/{digest}", s.track)
	mux.HandleFunc("POST /v1/tracks/{digest}/repair", s.repair)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.secret)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func (s *server) devices() ([]string, error) {
	files, err := os.ReadDir(filepath.Join(s.root, "devices"))
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(files))
	for _, file := range files {
		if file.Type().IsRegular() && validHex(file.Name(), 32) {
			ids = append(ids, file.Name())
		}
	}
	return ids, nil
}

func (s *server) listDevices(w http.ResponseWriter, _ *http.Request) {
	ids, err := s.devices()
	if err != nil {
		http.Error(w, "Cannot list devices", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ids)
}

func (s *server) device(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("device")
	if !validHex(id, 32) {
		http.Error(w, "Invalid device", http.StatusBadRequest)
		return
	}
	path := filepath.Join(s.root, "devices", id)
	if r.Method != http.MethodPut {
		w.Header().Set("Content-Type", "application/json")
		serveFile(w, r, path)
		return
	}

	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxManifest))
	if err != nil {
		http.Error(w, "Cannot read manifest", http.StatusBadRequest)
		return
	}
	var header struct {
		Version int    `json:"version"`
		Device  string `json:"device"`
	}
	if err := json.Unmarshal(data, &header); err != nil || header.Version != protocolVersion || header.Device != id {
		http.Error(w, "Invalid manifest", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		ids, err := s.devices()
		if err != nil || len(ids) >= maxDevices {
			http.Error(w, "Device limit reached", http.StatusInsufficientStorage)
			return
		}
	}
	if err := writeAtomic(path, bytes.NewReader(data)); err != nil {
		http.Error(w, "Cannot save manifest", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type trackIdentity struct {
	Digest string `json:"digest"`
	Bytes  int64  `json:"bytes"`
}

func (s *server) presentTracks(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128<<10))
	var tracks []trackIdentity
	if err != nil || json.Unmarshal(body, &tracks) != nil || len(tracks) > maxTrackBatch {
		http.Error(w, "Invalid track list", http.StatusBadRequest)
		return
	}
	present := make([]string, 0, len(tracks))
	for _, track := range tracks {
		if !validHex(track.Digest, 64) || track.Bytes < 1 || track.Bytes > maxTrack {
			http.Error(w, "Invalid track", http.StatusBadRequest)
			return
		}
		info, err := os.Lstat(filepath.Join(s.root, "tracks", track.Digest))
		if err != nil || !info.Mode().IsRegular() || info.Size() != track.Bytes {
			continue
		}
		if _, err := os.Lstat(filepath.Join(s.root, "repairs", track.Digest)); errors.Is(err, os.ErrNotExist) {
			present = append(present, track.Digest)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(present)
}

func (s *server) track(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	if !validHex(digest, 64) {
		http.Error(w, "Invalid track", http.StatusBadRequest)
		return
	}
	path := filepath.Join(s.root, "tracks", digest)
	repair := filepath.Join(s.root, "repairs", digest)
	if r.Method != http.MethodPut {
		if _, err := os.Lstat(repair); err == nil {
			w.Header().Set("X-Yap-Repair", "1")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		serveFile(w, r, path)
		return
	}
	if r.ContentLength < 1 || r.ContentLength > maxTrack {
		http.Error(w, "Invalid track size", http.StatusBadRequest)
		return
	}
	err := stageFile(path, func(file *os.File) error {
		h := sha256.New()
		length, err := io.Copy(io.MultiWriter(file, h), http.MaxBytesReader(w, r.Body, maxTrack))
		if err != nil {
			return err
		}
		if length != r.ContentLength || hex.EncodeToString(h.Sum(nil)) != digest {
			return errChecksum
		}
		return nil
	})
	if errors.Is(err, errChecksum) {
		http.Error(w, "Track checksum mismatch", http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		http.Error(w, "Cannot save track", http.StatusInternalServerError)
		return
	}
	os.Remove(repair)
	w.WriteHeader(http.StatusNoContent)
}

var errChecksum = errors.New("incorrect checksum")

func (s *server) repair(w http.ResponseWriter, r *http.Request) {
	digest := r.PathValue("digest")
	if !validHex(digest, 64) {
		http.Error(w, "Invalid track", http.StatusBadRequest)
		return
	}
	if err := writeAtomic(filepath.Join(s.root, "repairs", digest), bytes.NewReader(nil)); err != nil {
		http.Error(w, "Cannot register repair", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validHex(text string, length int) bool {
	if len(text) != length {
		return false
	}
	for _, ch := range []byte(text) {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func serveFile(w http.ResponseWriter, r *http.Request, path string) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

func writeAtomic(path string, contents io.Reader) error {
	return stageFile(path, func(file *os.File) error {
		_, err := io.Copy(file, contents)
		return err
	})
}

func stageFile(path string, write func(*os.File) error) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := write(file); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
