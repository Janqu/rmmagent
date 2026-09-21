package agent

import (
	"reflect"
	"testing"
)

func TestParseTaskIDs(t *testing.T) {
	got := parseTaskIDs(" 12, 13;14 x 0 -5 ")
	if want := []int{12, 13, 14}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
