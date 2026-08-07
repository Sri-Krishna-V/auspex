package model

import (
	"reflect"
	"strings"
	"testing"
)

// TestCELViewKeysMatchJSONTags machine-checks the promise documented on celView:
// every key it projects names a real JSON field of the Event struct. celFields
// is derived from celView, so this closes the remaining gap (celView ↔ struct):
// together they guarantee the CEL surface cannot silently drift from the wire
// schema. The allowed set is the json: tag of every Event field (the tag name
// before any ",omitempty"); a celView key outside that set is a typo or a
// field that was renamed/removed on the struct without updating the projection.
func TestCELViewKeysMatchJSONTags(t *testing.T) {
	allowed := make(map[string]struct{})
	rt := reflect.TypeOf(Event{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		allowed[name] = struct{}{}
	}

	for key := range (Event{}).celView() {
		if _, ok := allowed[key]; !ok {
			t.Errorf("celView key %q has no matching json tag on Event", key)
		}
	}
}
