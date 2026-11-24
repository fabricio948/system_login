package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

const defaultEnvFile = ".env"

// Config holds every runtime setting required by the application.
type Config struct {
	AppEnv                 string
	AppPort                int
	AccessTokenTTL         time.Duration
	RefreshTokenTTL        time.Duration
	RecoveryCodeTTL        time.Duration
	MaxFailedLoginAttempts int
	TempBlockDuration      time.Duration
	MaxRecoveryAttempts    int
	RecoveryCodePepper     string
	MySQL                  MySQL
}

// MySQL holds the database connection settings.
type MySQL struct {
	Host     string
	Port     int
	Database string
	User     string
	Password string
}

// Addr returns the host:port pair used by the driver.
func (m MySQL) Addr() string {
	return fmt.Sprintf("%s:%d", m.Host, m.Port)
}

// Load reads the default .env file and the process environment.
func Load() (*Config, error) {
	return LoadFile(defaultEnvFile)
}

// LoadFile reads the given .env file. Environment variables take precedence.
// A missing file is ignored so container deployments can rely on env vars only.
func LoadFile(path string) (*Config, error) {
	values, err := readEnvFile(path)
	if err != nil {
		return nil, err
	}

	get := func(key string) string {
		if value, ok := os.LookupEnv(key); ok {
			return strings.TrimSpace(value)
		}
		return values[key]
	}

	return build(get)
}

func build(get func(string) string) (*Config, error) {
	cfg := &Config{
		AppEnv:  envOrDefault(get, "APP_ENV", "development"),
		AppPort: 8080,
		MySQL: MySQL{
			Host:     envOrDefault(get, "MYSQL_HOST", "localhost"),
			Port:     3306,
			Database: get("MYSQL_DATABASE"),
			User:     get("MYSQL_USER"),
			Password: get("MYSQL_PASSWORD"),
		},
		RecoveryCodePepper: get("RECOVERY_CODE_PEPPER"),
	}

	var err error
	if cfg.AppPort, err = envInt(get, "APP_PORT", cfg.AppPort); err != nil {
		return nil, err
	}
	if cfg.MySQL.Port, err = envInt(get, "MYSQL_PORT", cfg.MySQL.Port); err != nil {
		return nil, err
	}
	if cfg.AccessTokenTTL, err = envDuration(get, "ACCESS_TOKEN_TTL"); err != nil {
		return nil, err
	}
	if cfg.RefreshTokenTTL, err = envDuration(get, "REFRESH_TOKEN_TTL"); err != nil {
		return nil, err
	}
	if cfg.RecoveryCodeTTL, err = envDuration(get, "RECOVERY_CODE_TTL"); err != nil {
		return nil, err
	}
	if cfg.TempBlockDuration, err = envDuration(get, "TEMP_BLOCK_DURATION"); err != nil {
		return nil, err
	}
	if cfg.MaxFailedLoginAttempts, err = envInt(get, "MAX_FAILED_LOGIN_ATTEMPTS", 0); err != nil {
		return nil, err
	}
	if cfg.MaxRecoveryAttempts, err = envInt(get, "MAX_RECOVERY_ATTEMPTS", 0); err != nil {
		return nil, err
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// MySQLConfig returns the driver configuration. ClientFoundRows makes
// RowsAffected report matched rows, which the repositories rely on.
func (c *Config) MySQLConfig() *mysql.Config {
	cfg := mysql.NewConfig()
	cfg.User = c.MySQL.User
	cfg.Passwd = c.MySQL.Password
	cfg.Net = "tcp"
	cfg.Addr = c.MySQL.Addr()
	cfg.DBName = c.MySQL.Database
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Collation = "utf8mb4_unicode_ci"
	cfg.ClientFoundRows = true
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	return cfg
}

// MySQLDSN returns the connection string used by sql.Open.
func (c *Config) MySQLDSN() string {
	return c.MySQLConfig().FormatDSN()
}

func (c *Config) validate() error {
	switch {
	case c.AppPort < 1 || c.AppPort > 65535:
		return errors.New("APP_PORT must be between 1 and 65535")
	case c.MySQL.Port < 1 || c.MySQL.Port > 65535:
		return errors.New("MYSQL_PORT must be between 1 and 65535")
	case c.MySQL.Host == "":
		return errors.New("MYSQL_HOST is required")
	case c.MySQL.Database == "":
		return errors.New("MYSQL_DATABASE is required")
	case c.MySQL.User == "":
		return errors.New("MYSQL_USER is required")
	case c.MySQL.Password == "":
		return errors.New("MYSQL_PASSWORD is required")
	case c.AccessTokenTTL <= 0:
		return errors.New("ACCESS_TOKEN_TTL must be positive")
	case c.RefreshTokenTTL <= 0:
		return errors.New("REFRESH_TOKEN_TTL must be positive")
	case c.RecoveryCodeTTL <= 0:
		return errors.New("RECOVERY_CODE_TTL must be positive")
	case c.TempBlockDuration <= 0:
		return errors.New("TEMP_BLOCK_DURATION must be positive")
	case c.MaxFailedLoginAttempts <= 0:
		return errors.New("MAX_FAILED_LOGIN_ATTEMPTS must be positive")
	case c.MaxRecoveryAttempts <= 0:
		return errors.New("MAX_RECOVERY_ATTEMPTS must be positive")
	case len(c.RecoveryCodePepper) < 32:
		return errors.New("RECOVERY_CODE_PEPPER must have at least 32 characters")
	}
	return nil
}

func readEnvFile(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}

	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("open env file %s: %w", path, err)
	}
	defer file.Close()

	values, err := parseEnv(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return values, nil
}

func parseEnv(reader io.Reader) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	line := 0

	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		raw = strings.TrimPrefix(raw, "export ")
		key, value, ok := strings.Cut(raw, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: missing '='", line)
		}

		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", line)
		}
		values[key] = unquote(strings.TrimSpace(value))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read env file: %w", err)
	}
	return values, nil
}

func unquote(value string) string {
	if len(value) < 2 {
		return value
	}
	first, last := value[0], value[len(value)-1]
	if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
		return value[1 : len(value)-1]
	}
	return value
}

func envOrDefault(get func(string) string, key, fallback string) string {
	if value := get(key); value != "" {
		return value
	}
	return fallback
}

func envInt(get func(string) string, key string, fallback int) (int, error) {
	raw := get(key)
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return value, nil
}

func envDuration(get func(string) string, key string) (time.Duration, error) {
	value, err := time.ParseDuration(get(key))
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", key, err)
	}
	return value, nil
}
