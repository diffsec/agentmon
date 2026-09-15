package cli

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/spf13/cobra"
)

// sanitizeTarPath validates that a tar entry path doesn't escape the restore directory.
func sanitizeTarPath(name string) (string, error) {
	// Clean the path
	clean := filepath.Clean(name)
	// Reject absolute paths
	if filepath.IsAbs(clean) {
		return "", fmt.Errorf("absolute path not allowed: %s", name)
	}
	// Reject paths that escape via ..
	if strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("path traversal not allowed: %s", name)
	}
	return clean, nil
}

func newBackupCmd() *cobra.Command {
	var output string
	var verify bool
	var configPath string

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Create a backup of agentmon data",
		RunE: func(cmd *cobra.Command, args []string) error {
			if output == "" {
				output = fmt.Sprintf("agentmon-backup-%s.tar.gz", time.Now().Format("20060102-150405"))
			}
			return createBackup(cmd, output, configPath, verify)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (default: agentmon-backup-<timestamp>.tar.gz)")
	cmd.Flags().BoolVar(&verify, "verify", false, "Verify backup after creation")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config file (defaults to AGENTMON_CONFIG or config.yml)")

	return cmd
}

func newRestoreCmd() *cobra.Command {
	var input string
	var verify bool
	var dryRun bool
	var configPath string

	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore agentmon data from backup",
		RunE: func(cmd *cobra.Command, args []string) error {
			if input == "" {
				return fmt.Errorf("--input is required")
			}
			return restoreBackup(cmd, input, configPath, verify, dryRun)
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "Input backup file (required)")
	cmd.Flags().BoolVar(&verify, "verify", false, "Verify restored data")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be restored without making changes")
	// Restore wrote to /etc/agentmon and /var/lib/agentmon whatever the
	// installation looked like. It needs the same config the backup was taken
	// against, or it puts the files somewhere the daemon does not read.
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config file, deciding where the restored files go (defaults to AGENTMON_CONFIG or config.yml)")
	cmd.MarkFlagRequired("input")

	return cmd
}

// backupPaths are the three locations backup reads and restore writes.
//
// Both used to hardcode /etc/agentmon and /var/lib/agentmon. Neither is
// writable by a non-root user, and both shipped units run the daemon as the
// logged-in user, so restore either failed outright or -- run as root against
// a user installation -- wrote files the daemon would never read.
type backupPaths struct {
	config   string
	auditDB  string
	policies string
}

// resolveBackupPaths reads the config the operator points at, and falls back
// to source-aware defaults rather than to a fixed system path.
func resolveBackupPaths(cmd *cobra.Command, configPath string) backupPaths {
	cfg, _, err := loadLocalConfig(configPath)
	resolved := configPath
	if strings.TrimSpace(resolved) == "" {
		resolved, _ = findConfigPath()
	}
	if err != nil || cfg == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not load config from %s: %v (using defaults)\n", resolved, err)
		cfg = &config.Config{}
	}
	p := backupPaths{
		config:   resolved,
		auditDB:  strings.TrimSpace(cfg.Audit.Storage.SQLitePath),
		policies: strings.TrimSpace(cfg.Policies.Dir),
	}
	if p.auditDB == "" {
		p.auditDB = filepath.Join(cfg.ResolvedDataDir(), "events.db")
	}
	if p.policies == "" {
		p.policies = filepath.Join(config.GetUserConfigDir(), "policies")
	}
	return p
}

func createBackup(cmd *cobra.Command, output, configPath string, verify bool) error {
	paths := resolveBackupPaths(cmd, configPath)
	configPath = paths.config
	auditDB := paths.auditDB
	policiesDir := paths.policies

	// Write to temp file first, rename on success to avoid partial backups
	tempFile := output + ".tmp"
	f, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}

	// Track whether we succeeded for cleanup
	success := false
	defer func() {
		if !success {
			os.Remove(tempFile)
		}
	}()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Track files added for verification
	var addedFiles []string

	// Backup config file
	if err := addFileToTar(tw, configPath, "config.yaml"); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not backup config: %v\n", err)
	} else {
		addedFiles = append(addedFiles, "config.yaml")
	}

	if err := addFileToTar(tw, auditDB, "events.db"); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not backup audit DB: %v\n", err)
	} else {
		addedFiles = append(addedFiles, "events.db")
	}

	if err := addDirToTar(tw, policiesDir, "policies"); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not backup policies: %v\n", err)
	}

	// Explicit close with error checking (instead of defer)
	if err := tw.Close(); err != nil {
		f.Close()
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gw.Close(); err != nil {
		f.Close()
		return fmt.Errorf("close gzip writer: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}

	// Rename temp file to final output
	if err := os.Rename(tempFile, output); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	success = true
	fmt.Fprintf(cmd.OutOrStdout(), "Backup created: %s\n", output)

	if verify {
		if err := verifyBackup(cmd, output); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Verification: OK\n")
	}

	return nil
}

// verifyBackup reads back a backup file and verifies its integrity.
func verifyBackup(cmd *cobra.Command, backupPath string) error {
	f, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	fileCount := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		// Verify path is safe
		if _, err := sanitizeTarPath(header.Name); err != nil {
			return fmt.Errorf("invalid tar entry %q: %w", header.Name, err)
		}

		// Verify we can read the file content
		hasher := sha256.New()
		n, err := io.Copy(hasher, tr)
		if err != nil {
			return fmt.Errorf("read content of %q: %w", header.Name, err)
		}

		if n != header.Size {
			return fmt.Errorf("size mismatch for %q: expected %d, got %d", header.Name, header.Size, n)
		}

		fileCount++
	}

	if fileCount == 0 {
		return fmt.Errorf("backup contains no files")
	}

	return nil
}

func restoreBackup(cmd *cobra.Command, input, configPath string, verify, dryRun bool) error {
	f, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	// Where the files go is decided by the config the operator points at, the
	// same resolution the backup was taken with, rather than by a fixed system
	// path this installation may not use or be able to write.
	paths := resolveBackupPaths(cmd, configPath)
	configDest := paths.config
	auditDBDest := paths.auditDB
	policiesDest := paths.policies

	restoredCount := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		// Sanitize path to prevent path traversal attacks
		safeName, err := sanitizeTarPath(header.Name)
		if err != nil {
			return fmt.Errorf("invalid tar entry: %w", err)
		}

		// Determine destination path based on tar entry name
		var destPath string
		switch {
		case safeName == "config.yaml":
			destPath = configDest
		case safeName == "events.db":
			destPath = auditDBDest
		case strings.HasPrefix(safeName, "policies/"):
			relPath := strings.TrimPrefix(safeName, "policies/")
			destPath = filepath.Join(policiesDest, relPath)
		default:
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: unknown entry %q, skipping\n", safeName)
			continue
		}

		if dryRun {
			fmt.Fprintf(cmd.OutOrStdout(), "Would restore: %s -> %s (%d bytes)\n", safeName, destPath, header.Size)
			continue
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Restoring: %s -> %s\n", safeName, destPath)

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", destPath, err)
		}

		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("create file %s: %w", destPath, err)
		}

		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return fmt.Errorf("write file %s: %w", destPath, err)
		}
		outFile.Close()

		// Restore modification time
		if err := os.Chtimes(destPath, header.ModTime, header.ModTime); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not set mtime for %s: %v\n", destPath, err)
		}

		restoredCount++
	}

	if restoredCount == 0 && !dryRun {
		return fmt.Errorf("no files were restored from backup")
	}

	if verify && !dryRun {
		// Verify restored files exist and have content
		for _, path := range []string{configDest, auditDBDest} {
			if info, err := os.Stat(path); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: restored file %s not accessible: %v\n", path, err)
			} else if info.Size() == 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: restored file %s is empty\n", path)
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Verification: OK\n")
	}

	return nil
}

func addFileToTar(tw *tar.Writer, srcPath, destName string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    destName,
		Size:    stat.Size(),
		Mode:    int64(stat.Mode()),
		ModTime: stat.ModTime(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = io.Copy(tw, f)
	return err
}

func addDirToTar(tw *tar.Writer, srcDir, destDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(destDir, relPath)
		return addFileToTar(tw, path, destPath)
	})
}
