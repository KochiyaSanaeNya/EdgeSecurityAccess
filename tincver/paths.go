package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	defaultPathsFile = "esa_paths.conf"
	envPathsFile     = "ESA_PATHS_FILE"
	envConfigDir     = "ESA_CONFIG_DIR"
	envTincBinDir    = "ESA_TINC_BIN_DIR"
	envTincReload    = "ESA_TINC_RELOAD"
)

type AppPaths struct {
	ConfigDir  string
	TincBinDir string
	TincReload bool
}

func (p *AppPaths) ESAConfigFile() string {
	return filepath.Join(p.ConfigDir, "esa.conf")
}

func (p *AppPaths) UsersFile() string {
	return filepath.Join(p.ConfigDir, "users.txt")
}

func (p *AppPaths) UserTincFile() string {
	return filepath.Join(p.ConfigDir, "usrtinc.conf")
}

func LoadOrCreateAppPaths() (*AppPaths, error) {
	pathsFile, err := appPathsFile()
	if err != nil {
		return nil, err
	}

	paths, exists, err := readAppPathsFile(pathsFile)
	if err != nil {
		return nil, err
	}

	if err := applyPathEnv(paths); err != nil {
		return nil, err
	}

	if !exists || paths.ConfigDir == "" || paths.TincBinDir == "" {
		paths, err = promptForAppPaths(paths)
		if err != nil {
			return nil, err
		}
		if err := writeAppPathsFile(pathsFile, paths); err != nil {
			return nil, err
		}
		logJSON("info", "path_config_created", logFields{"file": pathsFile})
	}

	if err := paths.Validate(); err != nil {
		return nil, fmt.Errorf("invalid path config %q: %w", pathsFile, err)
	}

	logJSON("info", "path_config_loaded", logFields{
		"file":         pathsFile,
		"config_dir":   paths.ConfigDir,
		"tinc_bin_dir": paths.TincBinDir,
		"tinc_reload":  paths.TincReload,
	})

	return paths, nil
}

func appPathsFile() (string, error) {
	if value := strings.TrimSpace(os.Getenv(envPathsFile)); value != "" {
		return filepath.Abs(value)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	cwdPath := filepath.Join(cwd, defaultPathsFile)
	if _, err := os.Stat(cwdPath); err == nil {
		return cwdPath, nil
	}

	if exe, err := os.Executable(); err == nil {
		exePath := filepath.Join(filepath.Dir(exe), defaultPathsFile)
		if _, err := os.Stat(exePath); err == nil {
			return exePath, nil
		}
	}

	return cwdPath, nil
}

func readAppPathsFile(path string) (*AppPaths, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &AppPaths{}, false, nil
		}
		return nil, false, fmt.Errorf("open path config: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logJSON("warn", "path_config_close_failed", logFields{"err": err.Error()})
		}
	}()

	paths := &AppPaths{}
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, false, fmt.Errorf("invalid path config line %d", lineNo)
		}
		key := strings.TrimSpace(strings.TrimPrefix(parts[0], "$"))
		value := strings.TrimSpace(parts[1])
		switch strings.ToLower(key) {
		case "configdir", "config_dir":
			paths.ConfigDir = filepath.Clean(value)
		case "tincbindir", "tinc_bin_dir":
			paths.TincBinDir = filepath.Clean(value)
		case "tincreload", "tinc_reload":
			enabled, err := parseBoolConfig(value)
			if err != nil {
				return nil, false, fmt.Errorf("invalid tincreload at line %d: %w", lineNo, err)
			}
			paths.TincReload = enabled
		default:
			logJSON("warn", "path_config_unknown_key", logFields{"key": key, "line": lineNo})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, false, fmt.Errorf("scan path config: %w", err)
	}
	return paths, true, nil
}

func applyPathEnv(paths *AppPaths) error {
	if value := strings.TrimSpace(os.Getenv(envConfigDir)); value != "" {
		paths.ConfigDir = filepath.Clean(value)
	}
	if value := strings.TrimSpace(os.Getenv(envTincBinDir)); value != "" {
		paths.TincBinDir = filepath.Clean(value)
	}
	if value := strings.TrimSpace(os.Getenv(envTincReload)); value != "" {
		enabled, err := parseBoolConfig(value)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", envTincReload, err)
		}
		paths.TincReload = enabled
	}
	return nil
}

func promptForAppPaths(paths *AppPaths) (*AppPaths, error) {
	reader := bufio.NewReader(os.Stdin)

	defaultConfigDir := paths.ConfigDir
	if defaultConfigDir == "" {
		if abs, err := filepath.Abs("config"); err == nil {
			defaultConfigDir = abs
		}
	}

	defaultTincBinDir := paths.TincBinDir
	if defaultTincBinDir == "" {
		defaultTincBinDir = defaultTincDirFromPath()
	}

	fmt.Println("First run path setup")
	fmt.Println("Please enter absolute paths. The values will be saved to " + defaultPathsFile + ".")
	fmt.Println("Required config files in config directory: esa.conf, users.txt, usrtinc.conf")

	configDir, err := promptPath(reader, "Config directory", defaultConfigDir)
	if err != nil {
		return nil, err
	}
	tincBinDir, err := promptPath(reader, "tinc package/bin directory", defaultTincBinDir)
	if err != nil {
		return nil, err
	}
	tincReload, err := promptBool(reader, "Reload tinc after host updates", false)
	if err != nil {
		return nil, err
	}

	return &AppPaths{
		ConfigDir:  filepath.Clean(configDir),
		TincBinDir: filepath.Clean(tincBinDir),
		TincReload: tincReload,
	}, nil
}

func promptPath(reader *bufio.Reader, label string, defaultValue string) (string, error) {
	for {
		if defaultValue != "" {
			fmt.Printf("%s [%s]: ", label, defaultValue)
		} else {
			fmt.Printf("%s: ", label)
		}
		value, err := reader.ReadString('\n')
		if err != nil && strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("read %s: %w", label, err)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			value = defaultValue
		}
		if value == "" {
			fmt.Println("Path is required.")
			continue
		}
		if !filepath.IsAbs(value) {
			fmt.Println("Path must be absolute.")
			continue
		}
		return value, nil
	}
}

func promptBool(reader *bufio.Reader, label string, defaultValue bool) (bool, error) {
	defaultText := "n"
	if defaultValue {
		defaultText = "y"
	}
	for {
		fmt.Printf("%s [y/N]: ", label)
		value, err := reader.ReadString('\n')
		if err != nil && strings.TrimSpace(value) == "" {
			return false, fmt.Errorf("read %s: %w", label, err)
		}
		value = strings.TrimSpace(value)
		if value == "" {
			value = defaultText
		}
		enabled, err := parseBoolConfig(value)
		if err != nil {
			fmt.Println("Please enter y or n.")
			continue
		}
		return enabled, nil
	}
}

func parseBoolConfig(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on", "enable", "enabled":
		return true, nil
	case "0", "false", "no", "n", "off", "disable", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean, got %q", value)
	}
}

func defaultTincDirFromPath() string {
	exe, err := exec.LookPath(tincExecutableName())
	if err != nil {
		return ""
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return filepath.Dir(exe)
	}
	return filepath.Dir(abs)
}

func writeAppPathsFile(path string, paths *AppPaths) error {
	content := "$configdir = " + paths.ConfigDir + "\n" +
		"$tincbindir = " + paths.TincBinDir + "\n" +
		"$tincreload = " + fmt.Sprintf("%t", paths.TincReload) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write path config: %w", err)
	}
	return nil
}

func (p *AppPaths) Validate() error {
	if strings.TrimSpace(p.ConfigDir) == "" {
		return fmt.Errorf("config directory is required; set it in %s or %s", defaultPathsFile, envConfigDir)
	}
	if !filepath.IsAbs(p.ConfigDir) {
		return fmt.Errorf("config directory must be absolute: %s", p.ConfigDir)
	}
	if err := requireDirectory(p.ConfigDir, "config directory"); err != nil {
		return err
	}
	for _, name := range []string{"esa.conf", "users.txt", "usrtinc.conf"} {
		path := filepath.Join(p.ConfigDir, name)
		if err := requireFile(path, name); err != nil {
			return err
		}
	}

	if strings.TrimSpace(p.TincBinDir) == "" {
		return fmt.Errorf("tinc package/bin directory is required; set it in %s or %s", defaultPathsFile, envTincBinDir)
	}
	if !filepath.IsAbs(p.TincBinDir) {
		return fmt.Errorf("tinc package/bin directory must be absolute: %s", p.TincBinDir)
	}
	if err := requireDirectory(p.TincBinDir, "tinc package/bin directory"); err != nil {
		return err
	}
	if p.TincReload {
		if _, err := resolveTincExecutable(p.TincBinDir); err != nil {
			return err
		}
	}
	return nil
}

func requireDirectory(path string, label string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %q is not accessible: %w", label, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %q is not a directory", label, path)
	}
	return nil
}

func requireFile(path string, label string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("required config file %s at %q is not accessible: %w", label, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("required config file %s at %q is a directory", label, path)
	}
	return nil
}

func resolveTincExecutable(tincBinDir string) (string, error) {
	for _, name := range tincExecutableNames() {
		exePath := filepath.Join(tincBinDir, name)
		info, err := os.Stat(exePath)
		if err != nil {
			continue
		}
		if info.IsDir() {
			return "", fmt.Errorf("tinc executable path %q is a directory", exePath)
		}
		return exePath, nil
	}
	return "", fmt.Errorf("tinc executable not found in %q; expected one of: %s", tincBinDir, strings.Join(tincExecutableNames(), ", "))
}

func resolveTincReloadCommand(tincBinDir string, network string) (string, []string, error) {
	exePath, err := resolveTincExecutable(tincBinDir)
	if err != nil {
		return "", nil, err
	}
	name := strings.ToLower(filepath.Base(exePath))
	if name == "tincd" || name == "tincd.exe" {
		return exePath, []string{"-n", network, "-kHUP"}, nil
	}
	return exePath, []string{"-n", network, "reload"}, nil
}

func tincExecutableNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"tinc.exe", "tincd.exe"}
	}
	return []string{"tinc", "tincd"}
}

func tincExecutableName() string {
	return tincExecutableNames()[0]
}
