package store

import "testing"

func TestMappingsStableNameAndIDOrder(t *testing.T) {
	s, _, _ := testStore(t)
	server := testNode(t, s, "server", "order-server")
	client := testNode(t, s, "client", "order-client")
	for i, name := range []string{"zeta", "alpha", "alpha"} {
		m := testMapping(server.ID, client.ID, 19020+i)
		m.Name = name
		if _, err := s.SaveMapping(m); err != nil {
			t.Fatal(err)
		}
	}
	var expected []string
	for retry := 0; retry < 25; retry++ {
		rows, err := s.Mappings()
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 3 || rows[0].Name != "alpha" || rows[1].Name != "alpha" || rows[2].Name != "zeta" || rows[0].ID >= rows[1].ID {
			t.Fatalf("unstable ordering: %+v", rows)
		}
		ids := []string{rows[0].ID, rows[1].ID, rows[2].ID}
		if retry > 0 {
			for i := range ids {
				if ids[i] != expected[i] {
					t.Fatalf("order changed: %v != %v", ids, expected)
				}
			}
		}
		expected = ids
	}
}
