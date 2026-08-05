package clientcli

import (
	"bytes"
	"context"
	"testing"
)

func TestCommandExposesClosedHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"version"}} {
		var output bytes.Buffer
		if status := (Command{}).Run(context.Background(), args, bytes.NewReader(nil), &output); status != 0 || !bytes.Contains(output.Bytes(), []byte(`"status":"ok"`)) {
			t.Fatalf("args=%v status=%d output=%s", args, status, output.Bytes())
		}
	}
}

func TestCommandDispatchFailsClosedWithoutComposition(t *testing.T) {
	var output bytes.Buffer
	if status := (Command{}).Run(context.Background(), []string{"session", "join"}, bytes.NewBufferString(`{}`), &output); status != 2 {
		t.Fatalf("status=%d output=%s", status, output.Bytes())
	}
}
