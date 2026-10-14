package agent

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestMeshHealthCheckinShape(t *testing.T) {
	a := &Agent{
		Logger: logrus.New(),
	}
	a.Logger.SetOutput(ioDiscard{})
	out := a.meshHealthCheckin()
	if _, ok := out["exists"].(bool); !ok {
		t.Fatalf("exists missing: %#v", out)
	}
	if _, ok := out["service_ok"].(bool); !ok {
		t.Fatalf("service_ok missing: %#v", out)
	}
	if stale, ok := out["stale"].(bool); !ok || stale {
		t.Fatalf("local check-in stale must be false: %#v", out)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
