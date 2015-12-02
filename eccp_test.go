package eccp

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fd/secp160r1"
)

func Test_Marshal_Unmarshal_P256(t *testing.T) {
	for i := 100; i > 0; i-- {
		_, x1, y1, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if x1 == nil {
			t.Fatalf("expected non-nil value for x1")
		}
		if y1 == nil {
			t.Fatalf("expected non-nil value for y1")
		}

		data := Marshal(elliptic.P256(), x1, y1)
		if data == nil {
			t.Fatalf("expected non-nil value for data")
		}

		x2, y2 := Unmarshal(elliptic.P256(), data)
		if x2 == nil {
			t.Fatalf("expected non-nil value for x2")
		}
		if y2 == nil {
			t.Fatalf("expected non-nil value for y2")
		}

		if !bytes.Equal(x1.Bytes(), x2.Bytes()) {
			t.Errorf("expected x1 to equal x2")
		}
		if !bytes.Equal(y1.Bytes(), y2.Bytes()) {
			t.Errorf("expected y1 to equal y2")
		}
	}
}

func Test_Marshal_Unmarshal_P160(t *testing.T) {
	for i := 100; i > 0; i-- {
		_, x1, y1, err := elliptic.GenerateKey(secp160r1.P160(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if x1 == nil {
			t.Fatalf("expected non-nil value for x1")
		}
		if y1 == nil {
			t.Fatalf("expected non-nil value for y1")
		}

		data := Marshal(secp160r1.P160(), x1, y1)
		if data == nil {
			t.Fatalf("expected non-nil value for data")
		}

		x2, y2 := Unmarshal(secp160r1.P160(), data)
		if x2 == nil {
			t.Fatalf("expected non-nil value for x2")
		}
		if y2 == nil {
			t.Fatalf("expected non-nil value for y2")
		}

		if !bytes.Equal(x1.Bytes(), x2.Bytes()) {
			t.Errorf("expected x1 to equal x2")
		}
		if !bytes.Equal(y1.Bytes(), y2.Bytes()) {
			t.Errorf("expected y1 to equal y2")
		}
	}
}
