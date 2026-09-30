package store

import (
	"testing"

	"veilink/internal/model"
)

func TestNodesStableNameAndIDOrder(t *testing.T) {
	s, _, _ := testStore(t)
	for _, name := range []string{"Zulu", "Alpha", "Alpha", "Beta"} {
		if _, err := s.SaveNode(model.Node{Name: name, Role: "client"}); err != nil {
			t.Fatal(err)
		}
	}
	for attempt := 0; attempt < 15; attempt++ {
		rows, err := s.Nodes()
		if err != nil || len(rows) != 4 {
			t.Fatalf("nodes: %d %v", len(rows), err)
		}
		for i := 1; i < len(rows); i++ {
			if rows[i-1].Name > rows[i].Name || (rows[i-1].Name == rows[i].Name && rows[i-1].ID >= rows[i].ID) {
				t.Fatalf("unstable node order: %+v", rows)
			}
		}
	}
}
