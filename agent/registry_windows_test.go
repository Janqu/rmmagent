//go:build windows

package agent

import "testing"

func TestNormalizeRegistryPage(t *testing.T) {
	page, pageSize := normalizeRegistryPage(0, -1)
	if page != 1 || pageSize != defaultRegistryPageSize {
		t.Fatalf("got page=%d pageSize=%d", page, pageSize)
	}
	page, pageSize = normalizeRegistryPage(2, maxRegistryPageSize+1)
	if page != 2 || pageSize != maxRegistryPageSize {
		t.Fatalf("got page=%d pageSize=%d", page, pageSize)
	}
}
