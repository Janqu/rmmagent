package agent

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const backupObjectV2 = "QDTBKP02"
const backupManifestLimit = 256 << 20

type backupStats struct {
	Files          int   `json:"files"`
	Uploaded       int64 `json:"bytes_uploaded"`
	Total          int64 `json:"bytes_total"`
	Reused         int64 `json:"bytes_reused"`
	ChunksUploaded int64 `json:"chunks_uploaded"`
	ChunksReused   int64 `json:"chunks_reused"`
	Unchanged      int64 `json:"files_unchanged"`
}

func (s backupStats) status(id int, state, message string, exitCode int) map[string]interface{} {
	return map[string]interface{}{"id": id, "status": state, "error": message, "exit_code": exitCode,
		"files": s.Files, "bytes_uploaded": s.Uploaded, "bytes_total": s.Total, "bytes_reused": s.Reused,
		"chunks_uploaded": s.ChunksUploaded, "chunks_reused": s.ChunksReused, "files_unchanged": s.Unchanged}
}

// Stable Gear table: changing this or the boundary rules changes deduplication.
// Hashes here choose boundaries; keyed SHA-256 identifies and verifies content.
var backupGear = func() [256]uint64 {
	var table [256]uint64
	for i := range table {
		hash := sha256.Sum256([]byte{byte(i)})
		table[i] = binary.LittleEndian.Uint64(hash[:8])
	}
	return table
}()

func backupChunks(ctx context.Context, reader io.Reader, limit int, emit func([]byte) error) error {
	if limit < 64 || limit > backupMaxChunk {
		return fmt.Errorf("invalid delta chunk limit")
	}
	average := 256 << 10
	for average > limit/4 {
		average >>= 1
	}
	minimum, maximum := average/4, average*4
	mask := uint64(average - 1)
	chunk := make([]byte, 0, maximum)
	buffer := make([]byte, 64<<10)
	var rolling uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(reader, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		for _, value := range buffer[:n] {
			chunk = append(chunk, value)
			rolling = rolling<<1 + backupGear[value]
			if len(chunk) >= minimum && (rolling&mask == 0 || len(chunk) == maximum) {
				if err := emit(chunk); err != nil {
					return err
				}
				chunk = chunk[:0]
				rolling = 0
			}
		}
		if err != nil {
			if len(chunk) > 0 {
				return emit(chunk)
			}
			return nil
		}
	}
}

func backupPack(key, aad, data []byte) ([]byte, error) {
	var compressed bytes.Buffer
	writer, err := zlib.NewWriterLevel(&compressed, zlib.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	flag := byte(0)
	if compressed.Len() < len(data) {
		data, flag = compressed.Bytes(), 1
	}
	header := append([]byte(backupObjectV2), flag)
	sealed, err := backupSeal(key, append(bytes.Clone(aad), header...), data)
	if err != nil {
		return nil, err
	}
	return append(header, sealed...), nil
}

func backupUnpack(key, aad, sealed []byte) ([]byte, error) {
	if len(sealed) > backupMaxChunk {
		return nil, fmt.Errorf("backup object exceeds size limit")
	}
	if !bytes.HasPrefix(sealed, []byte(backupObjectV2)) {
		return backupOpen(key, aad, sealed)
	}
	if len(sealed) <= len(backupObjectV2) {
		return nil, fmt.Errorf("truncated backup object")
	}
	header := sealed[:len(backupObjectV2)+1]
	raw, err := backupOpen(key, append(bytes.Clone(aad), header...), sealed[len(header):])
	if err != nil {
		return nil, err
	}
	switch header[len(header)-1] {
	case 0:
		return raw, nil
	case 1:
		reader, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		raw, err = io.ReadAll(io.LimitReader(reader, backupManifestLimit+1))
		if err != nil {
			return nil, err
		}
		if len(raw) > backupManifestLimit {
			return nil, fmt.Errorf("expanded backup object exceeds size limit")
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("unknown backup compression")
	}
}

type backupTransfer struct {
	agent         *Agent
	job           BackupJob
	encKey, idKey []byte
	known         map[string]bool
	stats         *backupStats
}

func (b *backupTransfer) remember(id string) {
	// ponytail: cap the in-memory cache; larger repositories recheck the server.
	if len(b.known) >= 65536 {
		b.known = make(map[string]bool)
	}
	b.known[id] = true
}

func (b *backupTransfer) existing(ctx context.Context, ids []string) (map[string]bool, error) {
	found := make(map[string]bool, len(ids))
	var pending []string
	seen := make(map[string]bool)
	for _, id := range ids {
		if !backupValidBlobID(id) {
			return nil, fmt.Errorf("invalid backup blob ID")
		}
		if b.known[id] {
			found[id] = true
		} else if !seen[id] {
			pending = append(pending, id)
			seen[id] = true
		}
	}
	for len(pending) > 0 {
		n := len(pending)
		if n > 128 {
			n = 128
		}
		batch := pending[:n]
		pending = pending[n:]
		if b.job.CheckURL != "" {
			var result struct {
				Existing []string `json:"existing"`
			}
			resp, err := b.agent.rClient.R().SetContext(ctx).SetBody(map[string]interface{}{"blob_ids": batch}).SetResult(&result).Post(b.job.CheckURL)
			if err != nil {
				return nil, err
			}
			if resp.StatusCode() != 200 {
				return nil, fmt.Errorf("blob lookup failed: %s", resp.Status())
			}
			for _, id := range result.Existing {
				if !seen[id] {
					return nil, fmt.Errorf("unexpected blob lookup response")
				}
				found[id] = true
				b.remember(id)
			}
		} else {
			for _, id := range batch {
				resp, err := b.agent.rClient.R().SetContext(ctx).Head(b.job.BlobURL + id + "/")
				if err != nil {
					return nil, err
				}
				switch resp.StatusCode() {
				case 204:
					found[id] = true
					b.remember(id)
				case 404:
				default:
					return nil, fmt.Errorf("blob lookup failed: %s", resp.Status())
				}
			}
		}
	}
	return found, nil
}

func (b *backupTransfer) put(ctx context.Context, id string, data []byte) error {
	sealed, err := backupPack(b.encKey, []byte(b.job.RepoID+":"+id), data)
	if err != nil {
		return err
	}
	if len(sealed) > backupMaxChunk {
		return fmt.Errorf("encrypted blob exceeds server limit")
	}
	resp, err := b.agent.rClient.R().SetContext(ctx).SetBody(sealed).Put(b.job.BlobURL + id + "/")
	if err != nil {
		return err
	}
	if resp.StatusCode() != 201 && resp.StatusCode() != 200 {
		return fmt.Errorf("blob upload failed: %s", resp.Status())
	}
	b.remember(id)
	b.stats.Uploaded += int64(len(sealed))
	return nil
}

func backupValidBlobID(id string) bool {
	return len(id) == 64 && strings.Trim(id, "0123456789abcdef") == ""
}

func (b *backupTransfer) get(ctx context.Context, id string) ([]byte, error) {
	if !backupValidBlobID(id) {
		return nil, fmt.Errorf("invalid backup blob ID")
	}
	resp, err := b.agent.rClient.R().SetContext(ctx).Get(b.job.BlobURL + id + "/")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("blob download failed: %s", resp.Status())
	}
	raw, err := backupUnpack(b.encKey, []byte(b.job.RepoID+":"+id), resp.Body())
	if err != nil {
		return nil, err
	}
	if len(raw) > backupMaxChunk || backupBlobID(b.idKey, raw) != id {
		return nil, fmt.Errorf("backup chunk integrity check failed")
	}
	return raw, nil
}

func (b *backupTransfer) decodeManifest(ctx context.Context, sealed []byte) (backupManifest, error) {
	var manifest backupManifest
	raw, err := backupUnpack(b.encKey, []byte("manifest:"+b.job.RepoID), sealed)
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return manifest, err
	}
	if manifest.RepoID != b.job.RepoID || manifest.Format > 2 {
		return manifest, fmt.Errorf("invalid backup manifest repository or format")
	}
	if len(manifest.Parts) > 0 {
		var data bytes.Buffer
		for _, id := range manifest.Parts {
			part, err := b.get(ctx, id)
			if err != nil {
				return manifest, err
			}
			if data.Len()+len(part) > backupManifestLimit {
				return manifest, fmt.Errorf("backup manifest exceeds size limit")
			}
			data.Write(part)
		}
		var full backupManifest
		if err := json.Unmarshal(data.Bytes(), &full); err != nil {
			return manifest, err
		}
		if full.RepoID != manifest.RepoID || full.RunID != manifest.RunID || full.Format != 2 || len(full.Parts) > 0 {
			return manifest, fmt.Errorf("invalid manifest parts")
		}
		manifest = full
	}
	return manifest, nil
}

func (b *backupTransfer) saveManifest(ctx context.Context, manifest backupManifest) error {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	// ponytail: manifests are held in memory up to 256 MiB; stream the index for larger fleets.
	if len(raw) > backupManifestLimit {
		return fmt.Errorf("backup manifest exceeds size limit")
	}
	if len(raw) > 4<<20 {
		manifest.Files = nil
		for start := 0; start < len(raw); start += 4 << 20 {
			end := start + 4<<20
			if end > len(raw) {
				end = len(raw)
			}
			part := raw[start:end]
			id := backupBlobID(b.idKey, part)
			found, err := b.existing(ctx, []string{id})
			if err != nil {
				return err
			}
			if !found[id] {
				if err := b.put(ctx, id, part); err != nil {
					return err
				}
			}
			manifest.Parts = append(manifest.Parts, id)
		}
		raw, err = json.Marshal(manifest)
		if err != nil {
			return err
		}
	}
	sealed, err := backupPack(b.encKey, []byte("manifest:"+b.job.RepoID), raw)
	if err != nil {
		return err
	}
	if len(sealed) > backupMaxChunk {
		return fmt.Errorf("encrypted manifest exceeds server limit")
	}
	resp, err := b.agent.rClient.R().SetContext(ctx).SetBody(sealed).Put(b.job.ManifestURL)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 201 {
		return fmt.Errorf("manifest upload failed: %s", resp.Status())
	}
	b.stats.Uploaded += int64(len(sealed))
	return nil
}
