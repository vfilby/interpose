package ppapi

import (
	"encoding/json"
	"testing"
)

func TestTaskRelatedDocumentShapes(t *testing.T) {
	for raw, want := range map[string]DocID{
		`{"task_id":"a","status":"SUCCESS","related_document":42}`:   42, // Paperless 2.x
		`{"task_id":"a","status":"SUCCESS","related_document":"42"}`: 42, // older releases
		`{"task_id":"a","status":"PENDING","related_document":null}`: 0,
		`{"task_id":"a","status":"PENDING"}`:                         0,
		`{"task_id":"a","status":"FAILURE","related_document":""}`:   0,
	} {
		var tk Task
		if err := json.Unmarshal([]byte(raw), &tk); err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		if tk.RelatedDocument != want {
			t.Errorf("%s: got %d, want %d", raw, tk.RelatedDocument, want)
		}
	}
	var tk Task
	if err := json.Unmarshal([]byte(`{"related_document":"x"}`), &tk); err == nil {
		t.Error("a non-numeric id was accepted")
	}
}
