//go:build darwin && cgo

// agentmon-macwrap: applies macOS sandbox profile with XPC restrictions,
// then execs the target command.
// Usage: agentmon-macwrap -- <command> [args...]
// Requires env AGENTMON_SANDBOX_CONFIG set to JSON config.

package main

/*
#cgo LDFLAGS: -framework Foundation
#include <sandbox.h>
#include <stdlib.h>
#include <stdint.h>

// sandbox_init_with_parameters is a private API not declared in public headers.
// It applies a custom SBPL profile string to the current process.
extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
    const char *const parameters[], char **errorbuf);

int apply_sandbox(const char *profile, char **errorbuf) {
    return sandbox_init_with_parameters(profile, 0, NULL, errorbuf);
}

void free_error(char *errorbuf) {
    // sandbox_free_error was deprecated in macOS 10.8
    // The error buffer is just malloc'd memory, so free() works
    free(errorbuf);
}

// sandbox_extension_consume consumes an extension token.
extern int64_t sandbox_extension_consume(const char *token);
*/
import "C"

import (
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"syscall"
	"unsafe"
)

func main() {
	log.SetFlags(0)

	cmd, args, err := validateArgs(os.Args)
	if err != nil {
		log.Fatalf("usage: %s -- <command> [args...]\nerror: %v", os.Args[0], err)
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Consume extension tokens before sandbox_init
	if len(cfg.ExtensionTokens) > 0 {
		consumeTokens(cfg.ExtensionTokens)
	}

	// Use compiled profile if provided, otherwise fall back to legacy generation
	profile := cfg.CompiledProfile
	if profile == "" {
		profile = generateProfile(cfg)
	}

	if err := applySandbox(profile); err != nil {
		log.Fatalf("apply sandbox: %v", err)
	}

	if err := syscall.Exec(cmd, args, sandboxedEnv(os.Environ())); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
}

// sandboxConfigVars carry the wrapper's own configuration and must not reach
// the process being sandboxed.
var sandboxConfigVars = []string{
	"AGENTMON_SANDBOX_CONFIG",
	"AGENTMON_SANDBOX_CONFIG_FILE",
}

// sandboxedEnv strips the wrapper's configuration from the environment handed
// to the child.
//
// os.Environ() was previously passed straight through, so the sandboxed process
// inherited AGENTMON_SANDBOX_CONFIG -- the full policy constraining it,
// including the compiled SBPL profile, the allowed path list and the
// mach-service allow/block lists (AUDIT M58). An agent could read the exact
// shape of its own sandbox and probe for the gaps. The config has already been
// consumed by loadConfig and applied by applySandbox before exec, so nothing
// downstream needs it.
func sandboxedEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, ok := strings.Cut(kv, "=")
		if ok && slices.Contains(sandboxConfigVars, name) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// applySandbox applies the SBPL profile using sandbox_init.
func applySandbox(profile string) error {
	cProfile := C.CString(profile)
	defer C.free(unsafe.Pointer(cProfile))

	var errorbuf *C.char
	rc := C.apply_sandbox(cProfile, &errorbuf)
	if rc != 0 {
		var errMsg string
		if errorbuf != nil {
			errMsg = C.GoString(errorbuf)
			C.free_error(errorbuf)
		}
		return fmt.Errorf("sandbox_init failed (rc=%d): %s", rc, errMsg)
	}
	return nil
}

// consumeTokens consumes sandbox extension tokens before sandbox_init
// so the child process inherits the consumed extensions through exec().
func consumeTokens(tokens []string) {
	for _, token := range tokens {
		cToken := C.CString(token)
		handle := C.sandbox_extension_consume(cToken)
		C.free(unsafe.Pointer(cToken))
		if handle == -1 {
			log.Printf("warning: failed to consume extension token (continuing)")
		}
	}
}
