package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func backupLANClient(address, fingerprint string) (*http.Client, error) {
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || n < 1024 || n > 65535 || ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) || !backupValidBlobID(fingerprint) {
		return nil, fmt.Errorf("invalid LAN endpoint")
	}
	// Trust the exact ephemeral certificate delivered over authenticated RMM messaging.
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) != 1 {
			return fmt.Errorf("invalid LAN certificate")
		}
		hash := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash[:])), []byte(fingerprint)) != 1 {
			return fmt.Errorf("LAN certificate mismatch")
		}
		return nil
	}}, DialContext: (&net.Dialer{Timeout: 8 * time.Second}).DialContext, ResponseHeaderTimeout: 30 * time.Second}
	return &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("LAN redirects forbidden") }}, nil
}

func backupLANRequest(ctx context.Context, client *http.Client, address, token, method, object, hash string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, "https://"+address+"/"+object, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Backup-SHA256", hash)
	response, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode, nil
}

func backupLANReceive(data map[string]string) map[string]interface{} {
	fail := func(err error) map[string]interface{} { return map[string]interface{}{"error": err.Error()} }
	if !backupRepoPattern.MatchString(data["token"]) || !backupRepoPattern.MatchString(data["repo"]) {
		return fail(fmt.Errorf("invalid LAN grant"))
	}
	run, err := strconv.Atoi(data["run"])
	if err != nil || run < 1 {
		return fail(fmt.Errorf("invalid run"))
	}
	if _, err := backupLANClient(data["address"], strings.Repeat("0", 64)); err != nil {
		return fail(err)
	}
	if result := backupDestinationCheck(data["path"]); result["ok"] != true {
		return result
	}
	probe := data["probe"] == "true"
	var root *os.Root
	if !probe {
		root, err = backupReplicaRoot(data["path"], data["repo"], true)
		if err != nil {
			return fail(err)
		}
		for _, dir := range []string{"blobs", "manifests"} {
			if err := root.MkdirAll(dir, 0700); err != nil {
				root.Close()
				return fail(err)
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		if root != nil {
			root.Close()
		}
		return fail(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		if root != nil {
			root.Close()
		}
		return fail(err)
	}
	template := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		if root != nil {
			root.Close()
		}
		return fail(err)
	}
	// ponytail: one active LAN receive session per address; competing sources retry their persisted queue.
	listener, err := tls.Listen("tcp", data["address"], &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		if root != nil {
			root.Close()
		}
		return fail(err)
	}
	var last atomic.Int64
	last.Store(time.Now().Unix())
	done := make(chan struct{})
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+data["token"])) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		last.Store(time.Now().Unix())
		if r.URL.Path == "/probe" && r.Method == http.MethodGet {
			w.WriteHeader(204)
			if probe {
				go func() { time.Sleep(100 * time.Millisecond); server.Close() }()
			}
			return
		}
		if r.URL.Path == "/finish" && r.Method == http.MethodPost {
			w.WriteHeader(204)
			go func() { time.Sleep(100 * time.Millisecond); server.Close() }()
			return
		}
		if probe {
			http.NotFound(w, r)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if len(parts) != 2 || (parts[0] != "blobs" && parts[0] != "manifests") || (parts[0] == "blobs" && !backupValidBlobID(parts[1])) || (parts[0] == "manifests" && parts[1] != strconv.Itoa(run)) {
			http.NotFound(w, r)
			return
		}
		hash := r.Header.Get("X-Backup-SHA256")
		if !backupValidBlobID(hash) {
			http.Error(w, "invalid hash", 400)
			return
		}
		name := filepath.Join(parts...)
		if r.Method == http.MethodHead {
			f, err := root.Open(name)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil || !info.Mode().IsRegular() || info.Size() > backupMaxChunk {
				http.Error(w, "invalid object", 409)
				return
			}
			h := sha256.New()
			if _, err := io.Copy(h, io.LimitReader(f, backupMaxChunk+1)); err != nil {
				http.Error(w, "read failed", 500)
				return
			}
			if hex.EncodeToString(h.Sum(nil)) != hash {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(204)
			return
		}
		if r.Method != http.MethodPut {
			w.WriteHeader(405)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, backupMaxChunk+1))
		if err != nil || len(body) == 0 || len(body) > backupMaxChunk {
			http.Error(w, "invalid size", 400)
			return
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != hash {
			http.Error(w, "hash mismatch", 422)
			return
		}
		if err := backupReplicaWrite(root, name, body); err != nil {
			http.Error(w, "write failed", 500)
			return
		}
		w.WriteHeader(201)
	})
	go func() {
		defer close(done)
		server.Serve(listener)
		if root != nil {
			root.Close()
		}
	}()
	go func() {
		timer := time.NewTicker(5 * time.Second)
		defer timer.Stop()
		started := time.Now()
		idle := 15 * time.Minute
		if probe {
			idle = 30 * time.Second
		}
		for {
			select {
			case <-done:
				return
			case <-timer.C:
				if time.Since(time.Unix(last.Load(), 0)) > idle || time.Since(started) > 24*time.Hour {
					server.Close()
					return
				}
			}
		}
	}()
	hash := sha256.Sum256(der)
	return map[string]interface{}{"ok": true, "fingerprint": hex.EncodeToString(hash[:])}
}

func (a *Agent) backupTransportProbe(data map[string]string, lan bool) map[string]interface{} {
	fail := func(err error) map[string]interface{} { return map[string]interface{}{"error": err.Error()} }
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if lan {
		client, err := backupLANClient(data["address"], data["fingerprint"])
		if err != nil {
			return fail(err)
		}
		defer client.CloseIdleConnections()
		code, err := backupLANRequest(ctx, client, data["address"], data["token"], http.MethodGet, "probe", "", nil)
		if err != nil {
			return fail(err)
		}
		if code != 204 {
			return fail(fmt.Errorf("LAN probe returned %d", code))
		}
	} else {
		if data["path"] != "" {
			if result := backupDestinationCheck(data["path"]); result["ok"] != true {
				return result
			}
		}
		response, err := a.rClient.R().SetContext(ctx).Get(data["url"])
		if err != nil {
			return fail(err)
		}
		if response.StatusCode() != 200 {
			return fail(fmt.Errorf("RMM API returned %d", response.StatusCode()))
		}
	}
	return map[string]interface{}{"ok": true}
}

func (a *Agent) backupLANCache(repo string) (*os.Root, error) {
	if !backupRepoPattern.MatchString(repo) {
		return nil, fmt.Errorf("invalid repo")
	}
	dir := filepath.Join(a.ProgramDir, "backup", "lan-cache", repo)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return os.OpenRoot(dir)
}

func (a *Agent) backupLANPoll(ctx context.Context) error {
	response, err := a.rClient.R().SetContext(ctx).Post("/qdt_backup/agent/lan-replicas/next/")
	if err != nil {
		return err
	}
	if response.StatusCode() == 204 || response.StatusCode() == 404 {
		return nil
	}
	if response.StatusCode() != 200 {
		return fmt.Errorf("LAN claim: %s", response.Status())
	}
	var job backupReplicaJob
	if err := json.Unmarshal(response.Body(), &job); err != nil {
		return err
	}
	if job.RunID <= 0 || !backupRepoPattern.MatchString(job.RepoID) || !backupRepoPattern.MatchString(job.Lease) {
		return fmt.Errorf("invalid LAN job")
	}
	endpoint := "/qdt_backup/agent/replicas/" + strconv.Itoa(job.RunID) + "/"
	copied, err := a.backupLANCopy(ctx, job, endpoint)
	state, message := "success", ""
	if err != nil {
		state, message = "failed", err.Error()
	}
	if report := a.backupReplicaReport(ctx, job, endpoint, state, copied, message); report != nil {
		return report
	}
	return err
}

func (a *Agent) backupLANCopy(ctx context.Context, job backupReplicaJob, endpoint string) (int64, error) {
	client, err := backupLANClient(job.LanAddress, job.Fingerprint)
	if err != nil {
		return 0, err
	}
	defer client.CloseIdleConnections()
	defer backupLANRequest(ctx, client, job.LanAddress, job.Lease, http.MethodPost, "finish", "", nil)
	cache, err := a.backupLANCache(job.RepoID)
	if err != nil {
		return 0, err
	}
	defer cache.Close()
	var copied int64
	after := ""
	last := time.Now()
	for {
		response, err := a.rClient.R().SetContext(ctx).SetHeader("X-Backup-Lease", job.Lease).SetQueryParam("after", after).Get(endpoint + "objects/")
		if err != nil {
			return copied, err
		}
		if response.StatusCode() != 200 {
			return copied, fmt.Errorf("LAN inventory: %s", response.Status())
		}
		var objects []backupReplicaObject
		if err := json.Unmarshal(response.Body(), &objects); err != nil {
			return copied, err
		}
		if len(objects) > 128 {
			return copied, fmt.Errorf("invalid LAN inventory")
		}
		for _, object := range objects {
			if !backupValidBlobID(object.ID) || !backupValidBlobID(object.SHA256) || object.ID <= after || object.Size < 1 || object.Size > backupMaxChunk {
				return copied, fmt.Errorf("invalid LAN object")
			}
			objectPath := "blobs/" + object.ID
			code, err := backupLANRequest(ctx, client, job.LanAddress, job.Lease, http.MethodHead, objectPath, object.SHA256, nil)
			if err != nil {
				return copied, err
			}
			if code != 204 {
				if code != 404 {
					return copied, fmt.Errorf("LAN object check: %d", code)
				}
				exists, err := backupReplicaVerify(cache, object.ID, object)
				if err != nil {
					return copied, err
				}
				var body []byte
				if exists {
					f, err := cache.Open(object.ID)
					if err != nil {
						return copied, err
					}
					body, err = io.ReadAll(io.LimitReader(f, backupMaxChunk+1))
					f.Close()
					if err != nil {
						return copied, err
					}
				} else {
					// Bootstrap historical or evicted ciphertext once; the second copy always travels source -> target over LAN.
					body, err = a.backupReplicaFetch(ctx, job, endpoint+objectPath+"/")
					if err != nil {
						return copied, err
					}
					sum := sha256.Sum256(body)
					if len(body) != object.Size || hex.EncodeToString(sum[:]) != object.SHA256 {
						return copied, fmt.Errorf("bootstrap checksum mismatch")
					}
					if err := backupReplicaWrite(cache, object.ID, body); err != nil {
						return copied, err
					}
				}
				code, err = backupLANRequest(ctx, client, job.LanAddress, job.Lease, http.MethodPut, objectPath, object.SHA256, body)
				if err != nil {
					return copied, err
				}
				if code != 201 {
					return copied, fmt.Errorf("LAN write: %d", code)
				}
				copied += int64(len(body))
			}
			after = object.ID
			if time.Since(last) > time.Minute {
				if err := a.backupReplicaReport(ctx, job, endpoint, "running", copied, ""); err != nil {
					return copied, err
				}
				last = time.Now()
			}
		}
		if len(objects) < 128 {
			break
		}
	}
	manifest, err := a.backupReplicaFetch(ctx, job, endpoint+"manifest/")
	if err != nil {
		return copied, err
	}
	hash := sha256.Sum256(manifest)
	code, err := backupLANRequest(ctx, client, job.LanAddress, job.Lease, http.MethodPut, "manifests/"+strconv.Itoa(job.RunID), hex.EncodeToString(hash[:]), manifest)
	if err != nil {
		return copied, err
	}
	if code != 201 {
		return copied, fmt.Errorf("LAN manifest: %d", code)
	}
	return copied + int64(len(manifest)), nil
}
