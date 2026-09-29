package control

import (
	"errors"
	"google.golang.org/protobuf/types/known/structpb"
	"testing"
	"veilink/internal/store"
)

func TestTrafficPayloadRejectsMalformedNumbersAndEntries(t *testing.T) {
	valid := map[string]any{"traffic_epoch": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "traffic_seq": 1, "traffic": map[string]any{"mapping": map[string]any{"up": 12, "down": 34}}}
	for _, mutation := range []func(map[string]any){
		func(m map[string]any) {},
		func(m map[string]any) { delete(m, "traffic_epoch") },
		func(m map[string]any) { m["traffic_seq"] = 1.5 },
		func(m map[string]any) { m["traffic_seq"] = -1 },
		func(m map[string]any) { m["traffic"] = "not a struct" },
		func(m map[string]any) { m["traffic"] = map[string]any{"mapping": map[string]any{"up": -1, "down": 2}} },
		func(m map[string]any) { m["traffic"] = map[string]any{"mapping": map[string]any{"up": 1.1, "down": 2}} },
	} {
		input := map[string]any{}
		for k, v := range valid {
			input[k] = v
		}
		mutation(input)
		message, err := structpb.NewStruct(input)
		if err != nil {
			t.Fatal(err)
		}
		_, _, totals, err := trafficPayload(message)
		if len(input) == 3 && input["traffic_seq"] == 1 && err == nil {
			if totals["mapping"] != (store.TrafficBytes{Up: 12, Down: 34}) {
				t.Fatal(totals)
			}
		} else if !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("malformed payload accepted: %v", input)
		}
	}
}
