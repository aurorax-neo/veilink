package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPEMRequestBudget(t *testing.T) {
	for _, tc := range []struct {
		path string
		size int
		want bool
	}{
		{"/api/v1/nodes", 200000, true}, {"/api/v1/nodes", 600000, false}, {"/api/v1/other", 70000, false},
	} {
		r := httptest.NewRequest("POST", tc.path, strings.NewReader(`{"value":"`+strings.Repeat("x", tc.size)+`"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		var v struct {
			Value string `json:"value"`
		}
		if got := decode(w, r, &v); got != tc.want {
			t.Fatalf("%s size%d got%v want%v", tc.path, tc.size, got, tc.want)
		}
	}
}
