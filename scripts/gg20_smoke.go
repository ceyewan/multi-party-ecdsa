package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type commandResult struct {
	name   string
	args   []string
	output string
	err    error
}

func main() {
	var (
		binDir      = flag.String("bin-dir", ".", "directory containing gg20 binaries")
		workDir     = flag.String("work-dir", "", "directory for generated shares and logs; defaults to a temporary directory")
		bindAddress = flag.String("bind-address", "127.0.0.1", "address passed to gg20_sm_manager --address")
		port        = flag.Int("port", 18001, "port passed to gg20_sm_manager --port")
		managerURL  = flag.String("manager-url", "", "client URL for the manager; defaults to http://127.0.0.1:<port>/")
		iterations  = flag.Int("iterations", 1, "number of full keygen/signing test iterations to run")
		timeout     = flag.Duration("timeout", 20*time.Minute, "overall timeout for all keygen and signing iterations")
		startDelay  = flag.Duration("party-start-delay", 500*time.Millisecond, "delay between starting party processes so manager-issued indexes match share indexes")
		keep        = flag.Bool("keep", false, "keep the work directory after a successful run")
		managerPath = flag.String("manager", "", "explicit path to gg20_sm_manager binary")
		keygenPath  = flag.String("keygen", "", "explicit path to gg20_keygen binary")
		signingPath = flag.String("signing", "", "explicit path to gg20_signing binary")
	)
	flag.Parse()

	if *managerURL == "" {
		*managerURL = fmt.Sprintf("http://127.0.0.1:%d/", *port)
	}
	if *iterations < 1 {
		fail("--iterations must be at least 1")
	}

	manager, err := resolveBinary(*binDir, *managerPath, "gg20_sm_manager")
	must("resolve manager binary", err)
	keygen, err := resolveBinary(*binDir, *keygenPath, "gg20_keygen")
	must("resolve keygen binary", err)
	signing, err := resolveBinary(*binDir, *signingPath, "gg20_signing")
	must("resolve signing binary", err)

	dir := *workDir
	if dir == "" {
		dir, err = os.MkdirTemp("", "gg20-smoke-*")
		must("create temp work directory", err)
	} else {
		must("create work directory", os.MkdirAll(dir, 0o755))
	}
	dir, err = filepath.Abs(dir)
	must("resolve work directory", err)

	fmt.Printf("GG20 smoke test\n")
	fmt.Printf("  manager: %s\n", manager)
	fmt.Printf("  keygen:  %s\n", keygen)
	fmt.Printf("  signing: %s\n", signing)
	fmt.Printf("  url:     %s\n", *managerURL)
	fmt.Printf("  work:    %s\n", dir)
	fmt.Printf("  rounds:  %d\n", *iterations)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	managerLog := filepath.Join(dir, "manager.log")
	managerOut, err := os.Create(managerLog)
	must("create manager log", err)
	defer managerOut.Close()

	managerCmd := exec.CommandContext(ctx, manager, "--address", *bindAddress, "--port", fmt.Sprint(*port))
	managerCmd.Stdout = managerOut
	managerCmd.Stderr = managerOut
	must("start manager", managerCmd.Start())
	managerDone := make(chan error, 1)
	go func() {
		managerDone <- managerCmd.Wait()
	}()
	defer stopProcess(managerCmd, managerDone)

	must("wait for manager", waitForManager(ctx, *managerURL, managerDone, managerLog))
	fmt.Println("manager is ready")

	signingCases := []signingCase{
		{name: "parties-1-2", parties: []int{1, 2}},
		{name: "parties-2-3", parties: []int{2, 3}},
		{name: "parties-1-3", parties: []int{1, 3}},
		{name: "parties-1-2-3", parties: []int{1, 2, 3}},
	}

	for iteration := 1; iteration <= *iterations; iteration++ {
		fmt.Printf("iteration %d/%d: keygen\n", iteration, *iterations)
		iterDir := filepath.Join(dir, fmt.Sprintf("iteration-%02d", iteration))
		must("create iteration directory", os.MkdirAll(iterDir, 0o755))

		roomSuffix := fmt.Sprintf("%d-%d", time.Now().UnixNano(), iteration)
		keygenRoom := "smoke-keygen-" + roomSuffix
		shares := []string{
			filepath.Join(iterDir, "local-share1.json"),
			filepath.Join(iterDir, "local-share2.json"),
			filepath.Join(iterDir, "local-share3.json"),
		}

		keygenResults := runParallel(ctx, *startDelay, []namedCommand{
			{name: "keygen-party-1", path: keygen, args: []string{"--address", *managerURL, "--room", keygenRoom, "--output", shares[0], "--index", "1", "--threshold", "1", "--number-of-parties", "3"}},
			{name: "keygen-party-2", path: keygen, args: []string{"--address", *managerURL, "--room", keygenRoom, "--output", shares[1], "--index", "2", "--threshold", "1", "--number-of-parties", "3"}},
			{name: "keygen-party-3", path: keygen, args: []string{"--address", *managerURL, "--room", keygenRoom, "--output", shares[2], "--index", "3", "--threshold", "1", "--number-of-parties", "3"}},
		})
		mustResults("keygen", keygenResults)
		for _, share := range shares {
			must("verify share "+share, requireNonEmptyFile(share))
		}
		fmt.Printf("iteration %d/%d: keygen completed\n", iteration, *iterations)

		for _, testCase := range signingCases {
			signRoom := fmt.Sprintf("smoke-sign-%s-%s", roomSuffix, testCase.name)
			messageHash := messageHashForCase(iteration, testCase)
			fmt.Printf("iteration %d/%d: signing %s\n", iteration, *iterations, testCase.partyList())
			signResults := runParallel(ctx, *startDelay, signingCommands(signing, *managerURL, signRoom, shares, testCase, messageHash))
			mustResults("signing "+testCase.partyList(), signResults)
			identity, err := ethereumIdentityFromShare(shares[testCase.parties[0]-1])
			must("extract keygen identity", err)
			for _, result := range signResults {
				must("verify "+result.name, verifyEthereumSignature(messageHash, result.output, identity))
			}
			fmt.Printf("iteration %d/%d: signing %s completed\n", iteration, *iterations, testCase.partyList())
		}
	}

	if !*keep && *workDir == "" {
		_ = os.RemoveAll(dir)
	} else {
		fmt.Printf("kept work directory: %s\n", dir)
	}
	fmt.Println("GG20 smoke test passed")
}

type signingCase struct {
	name    string
	parties []int
}

func (c signingCase) partyList() string {
	parts := make([]string, 0, len(c.parties))
	for _, party := range c.parties {
		parts = append(parts, fmt.Sprint(party))
	}
	return strings.Join(parts, ",")
}

type namedCommand struct {
	name string
	path string
	args []string
}

func signingCommands(signing, managerURL, room string, shares []string, testCase signingCase, messageHash string) []namedCommand {
	commands := make([]namedCommand, 0, len(testCase.parties))
	partyList := testCase.partyList()
	for position, party := range testCase.parties {
		commands = append(commands, namedCommand{
			name: fmt.Sprintf("sign-party-%d-with-%s", party, strings.ReplaceAll(partyList, ",", "-")),
			path: signing,
			args: []string{
				"--address", managerURL,
				"--room", room,
				"--local-share", shares[party-1],
				"--index", fmt.Sprint(position + 1),
				"--parties", partyList,
				"--data-to-sign", messageHash,
			},
		})
	}
	return commands
}

func messageHashForCase(iteration int, testCase signingCase) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("gg20-smoke|iteration=%d|parties=%s", iteration, testCase.partyList())))
	return hex.EncodeToString(digest[:])
}

type localShare struct {
	PublicKey struct {
		Curve string `json:"curve"`
		Point []int  `json:"point"`
	} `json:"y_sum_s"`
}

type ethereumIdentity struct {
	Address   string
	PublicKey *secpPoint
}

func ethereumIdentityFromShare(path string) (ethereumIdentity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ethereumIdentity{}, err
	}
	var share localShare
	if err := json.Unmarshal(raw, &share); err != nil {
		return ethereumIdentity{}, err
	}
	if share.PublicKey.Curve != "secp256k1" {
		return ethereumIdentity{}, fmt.Errorf("unexpected public key curve: %s", share.PublicKey.Curve)
	}
	pubBytes, err := intsToBytes(share.PublicKey.Point)
	if err != nil {
		return ethereumIdentity{}, err
	}
	pubKey, err := decompressSecp256k1(pubBytes)
	if err != nil {
		return ethereumIdentity{}, fmt.Errorf("parse keygen public key: %w", err)
	}
	return ethereumIdentity{
		Address:   ethereumAddress(pubKey),
		PublicKey: pubKey,
	}, nil
}

type gg20Signature struct {
	R struct {
		Curve  string `json:"curve"`
		Scalar []int  `json:"scalar"`
	} `json:"r"`
	S struct {
		Curve  string `json:"curve"`
		Scalar []int  `json:"scalar"`
	} `json:"s"`
	Recid int `json:"recid"`
}

func verifyEthereumSignature(messageHash, output string, identity ethereumIdentity) error {
	hashBytes, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(messageHash), "0x"))
	if err != nil {
		return fmt.Errorf("decode message hash: %w", err)
	}
	if len(hashBytes) != 32 {
		return fmt.Errorf("message hash length=%d, want 32 bytes", len(hashBytes))
	}
	signatureJSON, err := extractJSONObject(output)
	if err != nil {
		return err
	}
	signature, err := parseEthereumSignature(signatureJSON)
	if err != nil {
		return err
	}
	if !verifyECDSA(identity.PublicKey, hashBytes, signature.R, signature.S) {
		return fmt.Errorf("standard ECDSA verification failed for keygen address %s", identity.Address)
	}
	pubKey, err := recoverPublicKey(hashBytes, signature.R, signature.S, signature.Recid)
	if err != nil {
		return fmt.Errorf("recover signature: %w", err)
	}
	recoveredAddress := ethereumAddress(pubKey)
	if !strings.EqualFold(recoveredAddress, identity.Address) {
		return fmt.Errorf("recovered address=%s, want %s", recoveredAddress, identity.Address)
	}
	return nil
}

type ecdsaSignature struct {
	R     *big.Int
	S     *big.Int
	Recid int
}

func parseEthereumSignature(signatureJSON string) (ecdsaSignature, error) {
	var signature gg20Signature
	if err := json.Unmarshal([]byte(signatureJSON), &signature); err != nil {
		return ecdsaSignature{}, fmt.Errorf("parse signature JSON: %w; output=%s", err, signatureJSON)
	}
	if signature.R.Curve != "secp256k1" || signature.S.Curve != "secp256k1" {
		return ecdsaSignature{}, fmt.Errorf("unexpected signature curve r=%s s=%s", signature.R.Curve, signature.S.Curve)
	}
	if signature.Recid != 0 && signature.Recid != 1 {
		return ecdsaSignature{}, fmt.Errorf("invalid recovery id: %d", signature.Recid)
	}
	rBytes, err := scalarBytes(signature.R.Scalar)
	if err != nil {
		return ecdsaSignature{}, fmt.Errorf("r scalar: %w", err)
	}
	sBytes, err := scalarBytes(signature.S.Scalar)
	if err != nil {
		return ecdsaSignature{}, fmt.Errorf("s scalar: %w", err)
	}
	return ecdsaSignature{
		R:     new(big.Int).SetBytes(rBytes),
		S:     new(big.Int).SetBytes(sBytes),
		Recid: signature.Recid,
	}, nil
}

func scalarBytes(values []int) ([]byte, error) {
	bytes, err := intsToBytes(values)
	if err != nil {
		return nil, err
	}
	if len(bytes) > 32 {
		return nil, fmt.Errorf("length=%d, want at most 32 bytes", len(bytes))
	}
	padded := make([]byte, 32)
	copy(padded[32-len(bytes):], bytes)
	return padded, nil
}

func intsToBytes(values []int) ([]byte, error) {
	if len(values) == 0 {
		return nil, errors.New("empty byte array")
	}
	out := make([]byte, len(values))
	for i, value := range values {
		if value < 0 || value > 255 {
			return nil, fmt.Errorf("byte[%d]=%d out of range", i, value)
		}
		out[i] = byte(value)
	}
	return out, nil
}

func extractJSONObject(output string) (string, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "", errors.New("empty command output")
	}
	if json.Valid([]byte(trimmed)) {
		return trimmed, nil
	}
	lines := strings.Split(trimmed, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(lines[i])
		if candidate != "" && json.Valid([]byte(candidate)) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("command output does not contain JSON signature: %s", output)
}

var (
	secpP  = mustHexBig("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	secpN  = mustHexBig("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	secpGx = mustHexBig("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	secpGy = mustHexBig("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	secpB  = big.NewInt(7)
	secpG  = &secpPoint{x: secpGx, y: secpGy}
)

type secpPoint struct {
	x        *big.Int
	y        *big.Int
	infinity bool
}

func mustHexBig(value string) *big.Int {
	n, ok := new(big.Int).SetString(value, 16)
	if !ok {
		panic("invalid secp256k1 constant")
	}
	return n
}

func decompressSecp256k1(data []byte) (*secpPoint, error) {
	if len(data) == 65 && data[0] == 4 {
		point := &secpPoint{
			x: new(big.Int).SetBytes(data[1:33]),
			y: new(big.Int).SetBytes(data[33:65]),
		}
		if !isOnCurve(point) {
			return nil, errors.New("uncompressed public key is not on secp256k1")
		}
		return point, nil
	}
	if len(data) != 33 || (data[0] != 2 && data[0] != 3) {
		return nil, fmt.Errorf("unexpected public key length/prefix: len=%d", len(data))
	}
	x := new(big.Int).SetBytes(data[1:])
	if x.Cmp(secpP) >= 0 {
		return nil, errors.New("public key x coordinate is out of range")
	}
	alpha := modP(new(big.Int).Add(modP(new(big.Int).Exp(x, big.NewInt(3), secpP)), secpB))
	exp := new(big.Int).Add(secpP, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(alpha, exp, secpP)
	if modP(new(big.Int).Mul(y, y)).Cmp(alpha) != 0 {
		return nil, errors.New("public key x coordinate has no square root")
	}
	if byte(y.Bit(0)) != data[0]&1 {
		y.Sub(secpP, y)
	}
	point := &secpPoint{x: x, y: y}
	if !isOnCurve(point) {
		return nil, errors.New("compressed public key is not on secp256k1")
	}
	return point, nil
}

func ethereumAddress(point *secpPoint) string {
	pubKey := append(pad32(point.x), pad32(point.y)...)
	digest := keccak256(pubKey)
	return "0x" + hex.EncodeToString(digest[12:])
}

func verifyECDSA(pubKey *secpPoint, hash []byte, r, s *big.Int) bool {
	if pubKey == nil || !isOnCurve(pubKey) || !validScalar(r) || !validScalar(s) {
		return false
	}
	w := new(big.Int).ModInverse(s, secpN)
	if w == nil {
		return false
	}
	e := hashToScalar(hash)
	u1 := modN(new(big.Int).Mul(e, w))
	u2 := modN(new(big.Int).Mul(r, w))
	point := pointAdd(scalarBaseMult(u1), scalarMult(pubKey, u2))
	if point.infinity {
		return false
	}
	return modN(point.x).Cmp(r) == 0
}

func recoverPublicKey(hash []byte, r, s *big.Int, recid int) (*secpPoint, error) {
	if recid < 0 || recid > 3 {
		return nil, fmt.Errorf("invalid recovery id: %d", recid)
	}
	if !validScalar(r) || !validScalar(s) {
		return nil, errors.New("signature scalar out of range")
	}
	x := new(big.Int).Mul(big.NewInt(int64(recid/2)), secpN)
	x.Add(x, r)
	if x.Cmp(secpP) >= 0 {
		return nil, errors.New("recovery x coordinate is out of range")
	}
	rBytes := pad32(x)
	prefix := byte(2)
	if recid%2 == 1 {
		prefix = 3
	}
	R, err := decompressSecp256k1(append([]byte{prefix}, rBytes...))
	if err != nil {
		return nil, err
	}
	if !scalarMult(R, secpN).infinity {
		return nil, errors.New("recovery point has invalid order")
	}
	rInv := new(big.Int).ModInverse(r, secpN)
	if rInv == nil {
		return nil, errors.New("r has no inverse")
	}
	e := hashToScalar(hash)
	sR := scalarMult(R, s)
	eG := scalarBaseMult(e)
	q := scalarMult(pointAdd(sR, pointNeg(eG)), rInv)
	if q.infinity || !isOnCurve(q) {
		return nil, errors.New("recovered public key is invalid")
	}
	return q, nil
}

func validScalar(value *big.Int) bool {
	return value != nil && value.Sign() > 0 && value.Cmp(secpN) < 0
}

func hashToScalar(hash []byte) *big.Int {
	return modN(new(big.Int).SetBytes(hash))
}

func scalarBaseMult(k *big.Int) *secpPoint {
	return scalarMult(secpG, k)
}

func scalarMult(point *secpPoint, k *big.Int) *secpPoint {
	if point == nil || point.infinity || k.Sign() == 0 {
		return infinityPoint()
	}
	result := infinityPoint()
	addend := copyPoint(point)
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			result = pointAdd(result, addend)
		}
		addend = pointAdd(addend, addend)
	}
	return result
}

func pointAdd(a, b *secpPoint) *secpPoint {
	if a == nil || a.infinity {
		return copyPoint(b)
	}
	if b == nil || b.infinity {
		return copyPoint(a)
	}
	if a.x.Cmp(b.x) == 0 {
		if modP(new(big.Int).Add(a.y, b.y)).Sign() == 0 {
			return infinityPoint()
		}
		return pointDouble(a)
	}
	lambda := modP(new(big.Int).Sub(b.y, a.y))
	denominator := modP(new(big.Int).Sub(b.x, a.x))
	lambda.Mul(lambda, new(big.Int).ModInverse(denominator, secpP))
	lambda = modP(lambda)
	x3 := modP(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(lambda, lambda), a.x), b.x))
	y3 := modP(new(big.Int).Sub(new(big.Int).Mul(lambda, new(big.Int).Sub(a.x, x3)), a.y))
	return &secpPoint{x: x3, y: y3}
}

func pointDouble(point *secpPoint) *secpPoint {
	if point == nil || point.infinity || point.y.Sign() == 0 {
		return infinityPoint()
	}
	numerator := modP(new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(point.x, point.x)))
	denominator := modP(new(big.Int).Mul(big.NewInt(2), point.y))
	lambda := modP(new(big.Int).Mul(numerator, new(big.Int).ModInverse(denominator, secpP)))
	x3 := modP(new(big.Int).Sub(new(big.Int).Mul(lambda, lambda), new(big.Int).Mul(big.NewInt(2), point.x)))
	y3 := modP(new(big.Int).Sub(new(big.Int).Mul(lambda, new(big.Int).Sub(point.x, x3)), point.y))
	return &secpPoint{x: x3, y: y3}
}

func pointNeg(point *secpPoint) *secpPoint {
	if point == nil || point.infinity {
		return infinityPoint()
	}
	return &secpPoint{x: new(big.Int).Set(point.x), y: modP(new(big.Int).Neg(point.y))}
}

func isOnCurve(point *secpPoint) bool {
	if point == nil || point.infinity {
		return false
	}
	if point.x.Sign() < 0 || point.x.Cmp(secpP) >= 0 || point.y.Sign() < 0 || point.y.Cmp(secpP) >= 0 {
		return false
	}
	y2 := modP(new(big.Int).Mul(point.y, point.y))
	x3 := modP(new(big.Int).Exp(point.x, big.NewInt(3), secpP))
	x3 = modP(new(big.Int).Add(x3, secpB))
	return y2.Cmp(x3) == 0
}

func copyPoint(point *secpPoint) *secpPoint {
	if point == nil || point.infinity {
		return infinityPoint()
	}
	return &secpPoint{x: new(big.Int).Set(point.x), y: new(big.Int).Set(point.y)}
}

func infinityPoint() *secpPoint {
	return &secpPoint{infinity: true}
}

func modP(value *big.Int) *big.Int {
	return new(big.Int).Mod(value, secpP)
}

func modN(value *big.Int) *big.Int {
	return new(big.Int).Mod(value, secpN)
}

func pad32(value *big.Int) []byte {
	out := make([]byte, 32)
	bytes := value.Bytes()
	copy(out[32-len(bytes):], bytes)
	return out
}

func keccak256(data []byte) []byte {
	const rate = 136
	var state [25]uint64
	for len(data) >= rate {
		keccakAbsorbBlock(&state, data[:rate])
		keccakF1600(&state)
		data = data[rate:]
	}
	block := make([]byte, rate)
	copy(block, data)
	block[len(data)] ^= 0x01
	block[rate-1] ^= 0x80
	keccakAbsorbBlock(&state, block)
	keccakF1600(&state)

	out := make([]byte, 32)
	for i := 0; i < len(out)/8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], state[i])
	}
	return out
}

func keccakAbsorbBlock(state *[25]uint64, block []byte) {
	for i := 0; i < len(block)/8; i++ {
		state[i] ^= binary.LittleEndian.Uint64(block[i*8:])
	}
}

func keccakF1600(state *[25]uint64) {
	roundConstants := [24]uint64{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
		0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
		0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
		0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	}
	rotationConstants := [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
	piLane := [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}

	var column [5]uint64
	for round := 0; round < 24; round++ {
		for i := 0; i < 5; i++ {
			column[i] = state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]
		}
		for i := 0; i < 5; i++ {
			t := column[(i+4)%5] ^ bits.RotateLeft64(column[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				state[j+i] ^= t
			}
		}

		t := state[1]
		for i := 0; i < 24; i++ {
			j := piLane[i]
			column[0] = state[j]
			state[j] = bits.RotateLeft64(t, rotationConstants[i])
			t = column[0]
		}

		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				column[i] = state[j+i]
			}
			for i := 0; i < 5; i++ {
				state[j+i] = column[i] ^ ((^column[(i+1)%5]) & column[(i+2)%5])
			}
		}

		state[0] ^= roundConstants[round]
	}
}

func runParallel(ctx context.Context, startDelay time.Duration, commands []namedCommand) []commandResult {
	var wg sync.WaitGroup
	results := make([]commandResult, len(commands))
	for i, command := range commands {
		i, command := i, command
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = runCommand(ctx, command)
		}()
		if i < len(commands)-1 && startDelay > 0 {
			time.Sleep(startDelay)
		}
	}
	wg.Wait()
	return results
}

func runCommand(ctx context.Context, command namedCommand) commandResult {
	cmd := exec.CommandContext(ctx, command.path, command.args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return commandResult{
		name:   command.name,
		args:   append([]string{command.path}, command.args...),
		output: out.String(),
		err:    err,
	}
}

func resolveBinary(binDir, explicit, base string) (string, error) {
	if explicit != "" {
		return absExecutable(explicit)
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	candidates := []string{
		filepath.Join(binDir, fmt.Sprintf("%s_%s_%s%s", base, runtime.GOOS, runtime.GOARCH, ext)),
		filepath.Join(binDir, base+ext),
		filepath.Join(binDir, "target", "release", "examples", base+ext),
	}
	for _, candidate := range candidates {
		if path, err := absExecutable(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("could not find %s in %s", base, binDir)
}

func absExecutable(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory", path)
	}
	return filepath.Abs(path)
}

func waitForManager(ctx context.Context, managerURL string, managerDone <-chan error, managerLog string) error {
	client := http.Client{Timeout: time.Second}
	url := strings.TrimRight(managerURL, "/") + "/rooms/__gg20_smoke_health/issue_unique_idx"
	var lastErr error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("health status %s", resp.Status)
		} else {
			lastErr = err
		}

		select {
		case err := <-managerDone:
			logs, _ := os.ReadFile(managerLog)
			if err == nil {
				return fmt.Errorf("manager exited before becoming ready\nmanager log:\n%s", logs)
			}
			return fmt.Errorf("manager exited before becoming ready: %w\nmanager log:\n%s", err, logs)
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("%w: %v", ctx.Err(), lastErr)
			}
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func requireNonEmptyFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		return errors.New("file is empty")
	}
	return nil
}

func stopProcess(cmd *exec.Cmd, done <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

func mustResults(stage string, results []commandResult) {
	for _, result := range results {
		if result.err != nil {
			fail("%s failed in %s\ncommand: %s\noutput:\n%s", stage, result.name, strings.Join(result.args, " "), result.output)
		}
	}
}

func must(action string, err error) {
	if err != nil {
		fail("%s: %v", action, err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
