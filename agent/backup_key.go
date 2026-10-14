package agent

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

type backupKeyPackage struct {
	Version int    `json:"version"`
	RepoID  string `json:"repo_id"`
	Salt    []byte `json:"salt"`
	Sealed  []byte `json:"sealed"`
}

func (a *Agent) backupKey(repo string, data map[string]string) map[string]interface{} {
	result, err := a.backupKeyOperation(repo, data)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}
	return map[string]interface{}{"package": result, "ok": true}
}

func (a *Agent) backupKeyOperation(repo string, data map[string]string) (string, error) {
	if !backupRepoPattern.MatchString(repo) || len(data["password"]) < 12 || len(data["password"]) > 1024 {
		return "", fmt.Errorf("invalid repository or key password (minimum 12 characters)")
	}
	envelope := backupKeyPackage{Version: 1, RepoID: repo, Salt: make([]byte, 32)}
	if data["operation"] == "export" || data["operation"] == "prepare" {
		key, err := a.backupRepoKey(repo, data["operation"] == "prepare")
		if err != nil {
			return "", err
		}
		if _, err := rand.Read(envelope.Salt); err != nil {
			return "", err
		}
		wrapper, err := scrypt.Key([]byte(data["password"]), envelope.Salt, 32768, 8, 1, 32)
		if err != nil {
			return "", err
		}
		envelope.Sealed, err = backupSeal(wrapper, []byte("qdt-backup-key-v1:"+repo), key)
		if err != nil {
			return "", err
		}
		encoded, err := json.Marshal(envelope)
		return string(encoded), err
	}
	if data["operation"] != "import" || len(data["package"]) > 4096 {
		return "", fmt.Errorf("invalid key operation")
	}
	if err := json.Unmarshal([]byte(data["package"]), &envelope); err != nil {
		return "", err
	}
	if envelope.Version != 1 || envelope.RepoID != repo || len(envelope.Salt) != 32 || len(envelope.Sealed) != 72 {
		return "", fmt.Errorf("invalid key package")
	}
	wrapper, err := scrypt.Key([]byte(data["password"]), envelope.Salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	key, err := backupOpen(wrapper, []byte("qdt-backup-key-v1:"+repo), envelope.Sealed)
	if err != nil {
		return "", fmt.Errorf("wrong password or damaged key package")
	}
	if len(key) != 32 {
		return "", fmt.Errorf("invalid key length")
	}
	_, err = a.backupStoredKey(repo, false, key)
	clear(key)
	return "", err
}
