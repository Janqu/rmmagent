//go:build !windows

package agent

import (
	"github.com/sirupsen/logrus"
	"testing"
)

func TestBackupUnixProgramDirectory(t *testing.T) {
	a := New(logrus.New(), "test")
	if a.ProgramDir != "/opt/tacticalagent" || a.EXE != "/opt/tacticalagent/tacticalagent" {
		t.Fatalf("relative Unix agent paths: %q %q", a.ProgramDir, a.EXE)
	}
}
