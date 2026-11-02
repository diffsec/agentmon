package pkgcheck

import (
	"path/filepath"
	"strings"
	"unicode"
)

// InstallIntent captures the parsed intent of an install command.
type InstallIntent struct {
	Tool        string    // tool name (npm, pnpm, yarn, pip, uv, poetry)
	Ecosystem   Ecosystem // npm or pypi
	Packages    []string  // package names/specs from args
	BulkInstall bool      // true for "npm ci", "pip install -r", etc.
	OrigCommand string    // original command path
	OrigArgs    []string  // original args
}

// flagsWithValues lists flags that consume the next argument as a value.
// This is shared across package managers to skip flag values during package extraction.
var flagsWithValues = map[string]bool{
	"--registry":        true,
	"--save-prefix":     true,
	"--tag":             true,
	"--cache":           true,
	"--prefix":          true,
	"--target":          true,
	"-t":                true,
	"--index-url":       true,
	"--extra-index-url": true,
	"-i":                true,
	"-c":                true,
	"--constraint":      true,
	"--root":            true,
	"--python":          true,
	"--config-file":     true,
	"--group":           true,
	"-G":                true,
	"--timeout":         true,
	"--retries":         true,
	"--cache-dir":       true,
	"--trusted-host":    true,
	"--proxy":           true,
}

// ClassifyInstallCommand inspects a command and its arguments and returns an
// InstallIntent if the command is a recognized package install operation.
//
// Scope controls which installs are captured:
//   - "new_packages_only" (default): only commands that add new packages
//   - "all_installs": also captures bulk installs (npm ci, pip install -r, etc.)
//
// Returns nil if the command is not a recognized install.
func ClassifyInstallCommand(command string, args []string, scope string) *InstallIntent {
	if scope == "" {
		scope = "new_packages_only"
	}

	base := filepath.Base(command)
	// On non-Windows systems, filepath.Base won't split on '\',
	// so also check for a backslash separator for cross-platform safety.
	if idx := strings.LastIndex(base, `\`); idx >= 0 {
		base = base[idx+1:]
	}
	// Normalize to lowercase FIRST so that extension stripping is case-insensitive
	// (e.g., NPM.EXE -> npm.exe -> npm, not NPM.EXE -> NPM -> npm.exe).
	base = strings.ToLower(base)
	// Strip .exe, .cmd, .bat suffixes for Windows compatibility.
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".cmd")
	base = strings.TrimSuffix(base, ".bat")
	// A versioned name such as "pip3.15" is the same tool. Homebrew installs
	// pip3.15 next to pip3, and on macOS ES reports resolved paths.
	base = trimVersionSuffix(base)

	switch base {
	case "npm":
		return classifyNPM(command, args, scope)
	case "pnpm":
		return classifyPNPM(command, args, scope)
	case "yarn":
		return classifyYarn(command, args, scope)
	case "pip", "pip3":
		return classifyPip(command, args, scope)
	case "uv":
		return classifyUV(command, args, scope)
	case "poetry":
		return classifyPoetry(command, args, scope)
	default:
		return nil
	}
}

// trimVersionSuffix removes trailing ".<digits>" parts: "pip3.15" gives
// "pip3". The part that stays must hold a letter.
func trimVersionSuffix(name string) string {
	for {
		dot := strings.LastIndexByte(name, '.')
		if dot <= 0 || dot == len(name)-1 || !strings.ContainsFunc(name[:dot], unicode.IsLetter) {
			return name
		}
		if strings.Trim(name[dot+1:], "0123456789") != "" {
			return name
		}
		name = name[:dot]
	}
}

// UnwrapInstallCommand returns the package manager command inside a
// `python -m pip ...` command, as ("pip", the arguments after the module).
// Any other command comes back unchanged.
//
// The interpreter's own flags before -m are skipped. A flag that takes a
// value, such as -W or -X, is not expected before -m, so the first argument
// that does not start with "-" ends the search.
func UnwrapInstallCommand(command string, args []string) (string, []string) {
	base := strings.ToLower(filepath.Base(command))
	if !strings.HasPrefix(trimVersionSuffix(base), "python") {
		return command, args
	}
	for i, a := range args {
		if a == "-m" {
			if i+1 < len(args) {
				switch trimVersionSuffix(strings.ToLower(args[i+1])) {
				case "pip", "pip3":
					return "pip", args[i+2:]
				}
			}
			return command, args
		}
		if !strings.HasPrefix(a, "-") {
			return command, args
		}
	}
	return command, args
}

// classifyNPM handles npm install/i/add/ci commands.
func classifyNPM(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	sub, remaining := skipGlobalFlags(args)
	if sub == "" {
		return nil
	}

	switch sub {
	case "install", "i", "add":
		pkgs := extractPackages(remaining)
		if len(pkgs) > 0 {
			return &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    pkgs,
				BulkInstall: false,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		// "npm install" with no package args is a bulk install
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	case "ci":
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	default:
		return nil
	}
}

// classifyPNPM handles pnpm add/install/i commands.
func classifyPNPM(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	sub, remaining := skipGlobalFlags(args)
	if sub == "" {
		return nil
	}

	switch sub {
	case "add":
		pkgs := extractPackages(remaining)
		if len(pkgs) > 0 {
			return &InstallIntent{
				Tool:        "pnpm",
				Ecosystem:   EcosystemNPM,
				Packages:    pkgs,
				BulkInstall: false,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	case "install", "i":
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "pnpm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	default:
		return nil
	}
}

// classifyYarn handles yarn add/install commands.
func classifyYarn(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	sub, remaining := skipGlobalFlags(args)
	if sub == "" {
		return nil
	}

	switch sub {
	case "add":
		pkgs := extractPackages(remaining)
		if len(pkgs) > 0 {
			return &InstallIntent{
				Tool:        "yarn",
				Ecosystem:   EcosystemNPM,
				Packages:    pkgs,
				BulkInstall: false,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	case "install":
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "yarn",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	default:
		return nil
	}
}

// classifyPip handles pip/pip3 install commands.
func classifyPip(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	sub, remaining := skipGlobalFlags(args)
	if sub != "install" {
		return nil
	}

	// Check for -r / --requirement flag (bulk install from requirements file)
	if hasFlag(remaining, "-r") || hasFlag(remaining, "--requirement") {
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "pip",
				Ecosystem:   EcosystemPyPI,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil
	}

	pkgs := extractPackages(remaining)
	if len(pkgs) > 0 {
		return &InstallIntent{
			Tool:        "pip",
			Ecosystem:   EcosystemPyPI,
			Packages:    pkgs,
			BulkInstall: false,
			OrigCommand: command,
			OrigArgs:    args,
		}
	}

	return nil
}

// classifyUV handles uv pip install and uv add commands.
func classifyUV(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	sub, afterSub := skipGlobalFlags(args)
	if sub == "" {
		return nil
	}

	// "uv pip install ..."
	if sub == "pip" && len(afterSub) > 0 {
		pipSub, remaining := skipGlobalFlags(afterSub)
		if pipSub == "install" {
			// Check for -r / --requirement flag
			if hasFlag(remaining, "-r") || hasFlag(remaining, "--requirement") {
				if scope == "all_installs" {
					return &InstallIntent{
						Tool:        "uv",
						Ecosystem:   EcosystemPyPI,
						BulkInstall: true,
						OrigCommand: command,
						OrigArgs:    args,
					}
				}
				return nil
			}

			pkgs := extractPackages(remaining)
			if len(pkgs) > 0 {
				return &InstallIntent{
					Tool:        "uv",
					Ecosystem:   EcosystemPyPI,
					Packages:    pkgs,
					BulkInstall: false,
					OrigCommand: command,
					OrigArgs:    args,
				}
			}

			// "uv pip install" with no args is bulk
			if scope == "all_installs" {
				return &InstallIntent{
					Tool:        "uv",
					Ecosystem:   EcosystemPyPI,
					BulkInstall: true,
					OrigCommand: command,
					OrigArgs:    args,
				}
			}
			return nil
		}
		return nil
	}

	return nil
}

// classifyPoetry handles poetry add/install commands.
func classifyPoetry(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	sub, remaining := skipGlobalFlags(args)
	if sub == "" {
		return nil
	}

	switch sub {
	case "add":
		pkgs := extractPackages(remaining)
		if len(pkgs) > 0 {
			return &InstallIntent{
				Tool:        "poetry",
				Ecosystem:   EcosystemPyPI,
				Packages:    pkgs,
				BulkInstall: false,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	case "install":
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "poetry",
				Ecosystem:   EcosystemPyPI,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	default:
		return nil
	}
}

// extractPackages filters args to return only package names/specs,
// skipping flags and their values.
func extractPackages(args []string) []string {
	var pkgs []string
	skipNext := false

	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		if strings.HasPrefix(arg, "-") {
			// Check if this flag consumes the next arg
			// Handle --flag=value form
			if strings.Contains(arg, "=") {
				continue
			}
			if flagsWithValues[arg] {
				skipNext = true
			}
			continue
		}

		pkgs = append(pkgs, arg)
	}

	return pkgs
}

// hasFlag reports whether the given flag appears in args.
// Also matches the --flag=value compact form.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
		if strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

// skipGlobalFlags advances past leading flags (anything starting with "-")
// and their values before finding the subcommand. For flags that take values
// (found in flagsWithValues), the next argument is also skipped.
func skipGlobalFlags(args []string) (sub string, remaining []string) {
	i := 0
	for i < len(args) {
		if !strings.HasPrefix(args[i], "-") {
			return args[i], args[i+1:]
		}
		// Handle --flag=value compact form
		if strings.Contains(args[i], "=") {
			i++
			continue
		}
		// Check if this flag takes a value
		if flagsWithValues[args[i]] {
			i += 2 // skip flag and its value
		} else {
			i++ // skip boolean flag
		}
	}
	return "", nil
}
