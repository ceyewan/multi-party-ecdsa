package main

import (
	"encoding/hex"
	"testing"
)

func TestKeccak256EthereumEmptyString(t *testing.T) {
	got := hex.EncodeToString(keccak256(nil))
	const want = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	if got != want {
		t.Fatalf("keccak256(nil)=%s, want %s", got, want)
	}
}
