package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type upconf struct {
	username   string
	nodename   string
	userpublic string
	userip     string
	tincDir    string
	status     bool
}

const (
	tincReloadTimeout = 5 * time.Second
	maxCommandOutput  = 16 * 1024
)

var tincUpdateToken = make(chan struct{}, 1)

func updateTinc(ctx context.Context, conf *upconf, network string, tincBinDir string, tincReload bool) error {
	if err := ValidatePeer(conf); err != nil {
		fields := logFields{"err": err.Error()}
		if conf != nil {
			fields["user"] = conf.username
			fields["node"] = conf.nodename
			fields["ip"] = conf.userip
			fields["pubkey_hash"] = pubKeyHash(conf.userpublic)
		}
		logJSON("warn", "peer_validation_failed", fields)
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(network) == "" {
		return fmt.Errorf("tinc network is required")
	}
	if err := ValidateTincName(network); err != nil {
		return err
	}
	if strings.TrimSpace(conf.tincDir) == "" {
		return fmt.Errorf("tinc dir is required")
	}

	select {
	case tincUpdateToken <- struct{}{}:
		defer func() {
			<-tincUpdateToken
		}()
	case <-ctx.Done():
		return ctx.Err()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	tx, err := beginTincHostUpdate(conf)
	if err != nil {
		if conf.status {
			logJSON("error", "tinc_host_write_failed", logFields{
				"user":        conf.username,
				"node":        conf.nodename,
				"ip":          conf.userip,
				"pubkey_hash": pubKeyHash(conf.userpublic),
				"err":         err.Error(),
			})
		} else {
			logJSON("error", "tinc_host_remove_failed", logFields{
				"user": conf.username,
				"node": conf.nodename,
				"err":  err.Error(),
			})
		}
		return err
	}

	if conf.status {
		logJSON("info", "tinc_host_write_ok", logFields{"user": conf.username, "node": conf.nodename, "ip": conf.userip})
	} else {
		logJSON("info", "tinc_host_remove_ok", logFields{"user": conf.username, "node": conf.nodename})
	}

	if tincReload {
		if err := reloadTinc(ctx, network, tincBinDir); err != nil {
			if rollbackErr := tx.rollback(); rollbackErr != nil {
				logJSON("error", "tinc_host_rollback_failed", logFields{
					"user": conf.username,
					"node": conf.nodename,
					"err":  rollbackErr.Error(),
				})
			}
			return err
		}
	} else {
		logJSON("info", "tinc_reload_skipped", logFields{"network": network})
	}

	tx.commit()
	return nil
}

type tincHostTx struct {
	hostPath     string
	backupPath   string
	hadPrevious  bool
	committed    bool
	createdHosts bool
}

func beginTincHostUpdate(conf *upconf) (*tincHostTx, error) {
	hostsDir, hostPath, err := tincHostPaths(conf)
	if err != nil {
		return nil, err
	}
	createdHosts := false
	if _, err := os.Stat(hostsDir); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat tinc hosts dir: %w", err)
		}
		if err := os.MkdirAll(hostsDir, 0o700); err != nil {
			return nil, fmt.Errorf("create tinc hosts dir: %w", err)
		}
		createdHosts = true
	} else if err := ensureDirectory(hostsDir); err != nil {
		return nil, err
	}

	tx := &tincHostTx{
		hostPath:     hostPath,
		createdHosts: createdHosts,
	}
	if err := tx.backupExisting(hostsDir, conf.nodename); err != nil {
		return nil, err
	}
	if conf.status {
		if err := writeTincHostFile(hostsDir, hostPath, conf); err != nil {
			_ = tx.rollback()
			return nil, err
		}
		return tx, nil
	}
	if err := os.Remove(hostPath); err != nil && !os.IsNotExist(err) {
		_ = tx.rollback()
		return nil, fmt.Errorf("remove host file: %w", err)
	}
	if err := syncDir(hostsDir); err != nil {
		logJSON("warn", "tinc_hosts_dir_sync_failed", logFields{"err": err.Error()})
	}
	return tx, nil
}

func writeTincHost(conf *upconf) error {
	hostsDir, hostPath, err := tincHostPaths(conf)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(hostsDir, 0o700); err != nil {
		return fmt.Errorf("create tinc hosts dir: %w", err)
	}
	return writeTincHostFile(hostsDir, hostPath, conf)
}

func writeTincHostFile(hostsDir, hostPath string, conf *upconf) error {
	tmp, err := os.CreateTemp(hostsDir, "."+conf.nodename+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp host file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	content := buildTincHost(conf.userip, conf.userpublic)
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp host file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp host file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp host file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp host file: %w", err)
	}
	if err := replaceFile(tmpPath, hostPath); err != nil {
		return fmt.Errorf("replace host file: %w", err)
	}
	if err := syncDir(hostsDir); err != nil {
		logJSON("warn", "tinc_hosts_dir_sync_failed", logFields{"err": err.Error()})
	}
	return nil
}

func buildTincHost(userip string, userpublic string) string {
	return "Subnet = " + strings.TrimSpace(userip) + "\n" +
		"Ed25519PublicKey = " + strings.TrimRight(strings.TrimSpace(userpublic), "=") + "\n"
}

func removeTincHost(conf *upconf) error {
	hostsDir, hostPath, err := tincHostPaths(conf)
	if err != nil {
		return err
	}
	if err := os.Remove(hostPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove host file: %w", err)
	}
	if err := syncDir(hostsDir); err != nil {
		logJSON("warn", "tinc_hosts_dir_sync_failed", logFields{"err": err.Error()})
	}
	return nil
}

func tincHostPaths(conf *upconf) (string, string, error) {
	if conf == nil {
		return "", "", NewValidationError("request", "nil")
	}
	if err := ValidateTincName(conf.nodename); err != nil {
		return "", "", fmt.Errorf("invalid tinc node name: %w", err)
	}
	tincDir := filepath.Clean(conf.tincDir)
	if !isAbsConfigPath(tincDir) {
		return "", "", fmt.Errorf("tinc dir must be absolute")
	}
	hostsDir := filepath.Join(tincDir, "hosts")
	hostPath := filepath.Join(hostsDir, conf.nodename)
	if filepath.Dir(hostPath) != hostsDir {
		return "", "", fmt.Errorf("invalid tinc host path")
	}
	return hostsDir, hostPath, nil
}

func ensureDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func (tx *tincHostTx) backupExisting(hostsDir, nodename string) error {
	backup, err := os.CreateTemp(hostsDir, "."+nodename+"-backup-*.tmp")
	if err != nil {
		return fmt.Errorf("create host backup: %w", err)
	}
	tx.backupPath = backup.Name()
	defer func() {
		_ = backup.Close()
	}()

	current, err := os.Open(tx.hostPath)
	if err != nil {
		if os.IsNotExist(err) {
			_ = os.Remove(tx.backupPath)
			tx.backupPath = ""
			return nil
		}
		return fmt.Errorf("open existing host file: %w", err)
	}
	defer func() {
		_ = current.Close()
	}()

	if _, err := backup.ReadFrom(current); err != nil {
		return fmt.Errorf("write host backup: %w", err)
	}
	if err := backup.Sync(); err != nil {
		return fmt.Errorf("sync host backup: %w", err)
	}
	tx.hadPrevious = true
	return nil
}

func (tx *tincHostTx) rollback() error {
	if tx == nil || tx.committed {
		return nil
	}
	if tx.hadPrevious {
		if err := replaceFile(tx.backupPath, tx.hostPath); err != nil {
			return fmt.Errorf("restore host backup: %w", err)
		}
		if err := syncDir(filepath.Dir(tx.hostPath)); err != nil {
			logJSON("warn", "tinc_hosts_dir_sync_failed", logFields{"err": err.Error()})
		}
		return nil
	}
	if err := os.Remove(tx.hostPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove rolled-back host file: %w", err)
	}
	if tx.createdHosts {
		_ = os.Remove(filepath.Dir(tx.hostPath))
	}
	return nil
}

func (tx *tincHostTx) commit() {
	if tx == nil {
		return
	}
	tx.committed = true
	if tx.backupPath != "" {
		_ = os.Remove(tx.backupPath)
	}
}

func replaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if removeErr := os.Remove(dst); removeErr != nil && !os.IsNotExist(removeErr) {
		return removeErr
	}
	return os.Rename(src, dst)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = dir.Close()
	}()
	return dir.Sync()
}

func reloadTinc(ctx context.Context, network string, tincBinDir string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	tincPath, args, err := resolveTincReloadCommand(tincBinDir, network)
	if err != nil {
		return err
	}
	reloadCtx, cancel := context.WithTimeout(ctx, tincReloadTimeout)
	defer cancel()
	cmd := exec.CommandContext(reloadCtx, tincPath, args...)
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		logJSON("error", "tinc_reload_failed", logFields{
			"network": network,
			"tinc":    tincPath,
			"args":    strings.Join(args, " "),
			"err":     err.Error(),
			"out":     out.String(),
		})
		return fmt.Errorf("tinc reload failed: %v", err)
	}
	logJSON("info", "tinc_reload_ok", logFields{"network": network, "tinc": tincPath, "args": strings.Join(args, " ")})
	return nil
}

type limitedBuffer struct {
	buf       bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := maxCommandOutput - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	if !b.truncated {
		return b.buf.String()
	}
	return b.buf.String() + "... [truncated]"
}
