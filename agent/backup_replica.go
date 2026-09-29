package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type backupReplicaJob struct {
	RunID  int    `json:"run_id"`
	RepoID string `json:"repo_id"`
	Path   string `json:"path"`
	Lease  string `json:"lease"`
}

type backupReplicaObject struct {
	ID     string `json:"id"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

// One worker per destination limits NAS I/O and lets many source devices share it.
func (a *Agent) backupReplicaWorker() {
	for {
		if err := a.backupReplicaPoll(context.Background()); err != nil {
			a.Logger.Debugln("Backup copy:", err)
		}
		time.Sleep(time.Minute)
	}
}

func (a *Agent) backupReplicaPoll(ctx context.Context) error {
	var job backupReplicaJob
	response, err := a.rClient.R().SetContext(ctx).Post("/qdt_backup/agent/replicas/next/")
	if err != nil {
		return err
	}
	if response.StatusCode() == 204 || response.StatusCode() == 404 {
		return nil
	}
	if response.StatusCode() != 200 {
		return fmt.Errorf("copy claim: %s", response.Status())
	}
	if err := json.Unmarshal(response.Body(), &job); err != nil {
		return err
	}
	if job.RunID <= 0 || !backupRepoPattern.MatchString(job.RepoID) || !backupRepoPattern.MatchString(job.Lease) {
		return fmt.Errorf("invalid copy job")
	}
	endpoint := "/qdt_backup/agent/replicas/" + strconv.Itoa(job.RunID) + "/"
	copied, err := a.backupReplicaCopy(ctx, job, endpoint)
	state, message := "success", ""
	if err != nil {
		state, message = "failed", err.Error()
	}
	if statusErr := a.backupReplicaReport(ctx, job, endpoint, state, copied, message); statusErr != nil {
		return statusErr
	}
	return err
}

func (a *Agent) backupReplicaReport(ctx context.Context, job backupReplicaJob, endpoint, state string, copied int64, message string) error {
	response, err := a.rClient.R().SetContext(ctx).SetHeader("X-Backup-Lease", job.Lease).
		SetBody(map[string]interface{}{"status": state, "bytes_copied": copied, "error": message}).Post(endpoint + "status/")
	if err != nil {
		return err
	}
	if response.StatusCode() != 200 {
		return fmt.Errorf("copy status: %s", response.Status())
	}
	return nil
}

func backupReplicaRoot(path, repo string, create bool) (*os.Root, error) {
	if !filepath.IsAbs(path) || !backupRepoPattern.MatchString(repo) {
		return nil, fmt.Errorf("invalid replica destination")
	}
	// The selected directory must already exist; do not create the user-selected path.
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Join("qdt-backup", repo)
	if create {
		if err := root.MkdirAll(name, 0700); err != nil {
			return nil, err
		}
	}
	return root.OpenRoot(name)
}

func (a *Agent) backupReplicaCopy(ctx context.Context, job backupReplicaJob, endpoint string) (int64, error) {
	root, err := backupReplicaRoot(job.Path, job.RepoID, true)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	for _, dir := range []string{"blobs", "manifests"} {
		if err := root.MkdirAll(dir, 0700); err != nil {
			return 0, err
		}
	}
	var copied int64
	after := ""
	lastReport := time.Now()
	for {
		response, err := a.rClient.R().SetContext(ctx).SetHeader("X-Backup-Lease", job.Lease).SetQueryParam("after", after).Get(endpoint + "objects/")
		if err != nil {
			return copied, err
		}
		if response.StatusCode() != 200 {
			return copied, fmt.Errorf("copy inventory: %s", response.Status())
		}
		var objects []backupReplicaObject
		if err := json.Unmarshal(response.Body(), &objects); err != nil {
			return copied, err
		}
		if len(objects) > 128 {
			return copied, fmt.Errorf("invalid copy inventory")
		}
		for _, object := range objects {
			if !backupValidBlobID(object.ID) || !backupValidBlobID(object.SHA256) || object.ID <= after || object.Size < 1 || object.Size > backupMaxChunk {
				return copied, fmt.Errorf("invalid copy object")
			}
			name := filepath.Join("blobs", object.ID)
			exists, err := backupReplicaVerify(root, name, object)
			if err != nil {
				return copied, err
			}
			if !exists {
				data, err := a.backupReplicaFetch(ctx, job, endpoint+"blobs/"+object.ID+"/")
				if err != nil {
					return copied, err
				}
				hash := sha256.Sum256(data)
				if len(data) != object.Size || hex.EncodeToString(hash[:]) != object.SHA256 {
					return copied, fmt.Errorf("copy object checksum mismatch")
				}
				if err := backupReplicaWrite(root, name, data); err != nil {
					return copied, err
				}
				copied += int64(len(data))
			}
			after = object.ID
			if time.Since(lastReport) > time.Minute {
				if err := a.backupReplicaReport(ctx, job, endpoint, "running", copied, ""); err != nil {
					return copied, err
				}
				lastReport = time.Now()
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
	// Publish the snapshot only after all encrypted objects have been verified on disk.
	if err := backupReplicaWrite(root, filepath.Join("manifests", strconv.Itoa(job.RunID)), manifest); err != nil {
		return copied, err
	}
	return copied + int64(len(manifest)), nil
}

func backupReplicaVerify(root *os.Root, name string, object backupReplicaObject) (bool, error) {
	f, err := root.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("replica object is not a regular file")
	}
	if info.Size() != int64(object.Size) {
		return false, nil
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(f, backupMaxChunk+1)); err != nil {
		return false, err
	}
	return hex.EncodeToString(hash.Sum(nil)) == object.SHA256, nil
}

func (a *Agent) backupReplicaFetch(ctx context.Context, job backupReplicaJob, url string) ([]byte, error) {
	resp, err := a.rClient.R().SetContext(ctx).SetHeader("X-Backup-Lease", job.Lease).Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("copy download: %s", resp.Status())
	}
	body := resp.Body()
	if len(body) == 0 || len(body) > backupMaxChunk {
		return nil, fmt.Errorf("invalid copy object size")
	}
	return body, nil
}

func backupReplicaWrite(root *os.Root, name string, data []byte) error {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temp := name + "." + hex.EncodeToString(random[:]) + ".tmp"
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename(temp, name)
}

// Bounded RPC responses stay below the broker limit; the source verifies/decrypts.
func (a *Agent) backupReplicaRead(data map[string]string) map[string]interface{} {
	fail := func(err error) map[string]interface{} { return map[string]interface{}{"error": err.Error()} }
	root, err := backupReplicaRoot(data["path"], data["repo"], false)
	if err != nil {
		return fail(err)
	}
	defer root.Close()
	object := data["object"]
	parts := strings.Split(object, "/")
	if len(parts) != 2 {
		return fail(fmt.Errorf("invalid copy object"))
	}
	if parts[0] == "blobs" {
		if !backupValidBlobID(parts[1]) {
			return fail(fmt.Errorf("invalid blob"))
		}
	} else if parts[0] == "manifests" {
		id, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != parts[1] {
			return fail(fmt.Errorf("invalid manifest"))
		}
	} else {
		return fail(fmt.Errorf("invalid copy object"))
	}
	offset, err := strconv.ParseInt(data["offset"], 10, 64)
	if err != nil || offset < 0 || offset > backupMaxChunk {
		return fail(fmt.Errorf("invalid offset"))
	}
	f, err := root.Open(filepath.Join(parts...))
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() || info.Size() > backupMaxChunk || offset > info.Size() {
		return fail(fmt.Errorf("invalid copy file"))
	}
	buf := make([]byte, 512<<10)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return fail(err)
	}
	return map[string]interface{}{"data": base64.StdEncoding.EncodeToString(buf[:n]), "eof": offset+int64(n) >= info.Size()}
}
