package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
		timeout     = flag.Duration("timeout", 2*time.Minute, "overall timeout for keygen and signing")
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

	roomSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	keygenRoom := "smoke-keygen-" + roomSuffix
	shares := []string{
		filepath.Join(dir, "local-share1.json"),
		filepath.Join(dir, "local-share2.json"),
		filepath.Join(dir, "local-share3.json"),
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
	fmt.Println("keygen completed")

	signRoom := "smoke-sign-" + roomSuffix
	signResults := runParallel(ctx, *startDelay, []namedCommand{
		{name: "sign-party-1", path: signing, args: []string{"--address", *managerURL, "--room", signRoom, "--local-share", shares[0], "--parties", "1,2", "--data-to-sign", "offline-system-smoke-test"}},
		{name: "sign-party-2", path: signing, args: []string{"--address", *managerURL, "--room", signRoom, "--local-share", shares[1], "--parties", "1,2", "--data-to-sign", "offline-system-smoke-test"}},
	})
	mustResults("signing", signResults)
	for _, result := range signResults {
		if !strings.Contains(result.output, "r") || !strings.Contains(result.output, "s") {
			fail("%s did not print a JSON-like ECDSA signature:\n%s", result.name, result.output)
		}
	}
	fmt.Println("signing completed")

	if !*keep && *workDir == "" {
		_ = os.RemoveAll(dir)
	} else {
		fmt.Printf("kept work directory: %s\n", dir)
	}
	fmt.Println("GG20 smoke test passed")
}

type namedCommand struct {
	name string
	path string
	args []string
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
