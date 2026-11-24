package config

import (
	"strings"
	"testing"
	"time"
)

func validValues() map[string]string {
	return map[string]string{
		"APP_ENV":                   "test",
		"APP_PORT":                  "9090",
		"ACCESS_TOKEN_TTL":          "15m",
		"REFRESH_TOKEN_TTL":         "168h",
		"RECOVERY_CODE_TTL":         "15m",
		"MAX_FAILED_LOGIN_ATTEMPTS": "4",
		"TEMP_BLOCK_DURATION":       "10m",
		"MAX_RECOVERY_ATTEMPTS":     "5",
		"RECOVERY_CODE_PEPPER":      strings.Repeat("a", 64),
		"MYSQL_HOST":                "db",
		"MYSQL_PORT":                "3307",
		"MYSQL_DATABASE":            "system_login",
		"MYSQL_USER":                "app_user",
		"MYSQL_PASSWORD":            "secret",
	}
}

func TestBuild(t *testing.T) {
	values := validValues()
	cfg, err := build(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("build returned error: %v", err)
	}

	if cfg.AppPort != 9090 {
		t.Errorf("AppPort = %d, want 9090", cfg.AppPort)
	}
	if cfg.MySQL.Addr() != "db:3307" {
		t.Errorf("MySQL address = %q, want %q", cfg.MySQL.Addr(), "db:3307")
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want 15m", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 168*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 168h", cfg.RefreshTokenTTL)
	}
	if cfg.MaxFailedLoginAttempts != 4 {
		t.Errorf("MaxFailedLoginAttempts = %d, want 4", cfg.MaxFailedLoginAttempts)
	}
	if cfg.MySQLDSN() == "" {
		t.Error("MySQLDSN returned an empty string")
	}
}

func TestBuildDefaults(t *testing.T) {
	values := validValues()
	delete(values, "APP_ENV")
	delete(values, "APP_PORT")
	delete(values, "MYSQL_HOST")
	delete(values, "MYSQL_PORT")

	cfg, err := build(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("build returned error: %v", err)
	}
	if cfg.AppEnv != "development" {
		t.Errorf("AppEnv = %q, want development", cfg.AppEnv)
	}
	if cfg.AppPort != 8080 {
		t.Errorf("AppPort = %d, want 8080", cfg.AppPort)
	}
	if cfg.MySQL.Host != "localhost" || cfg.MySQL.Port != 3306 {
		t.Errorf("MySQL = %s:%d, want localhost:3306", cfg.MySQL.Host, cfg.MySQL.Port)
	}
}

func TestBuildValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"missing pepper", func(v map[string]string) { v["RECOVERY_CODE_PEPPER"] = "" }},
		{"short pepper", func(v map[string]string) { v["RECOVERY_CODE_PEPPER"] = "short" }},
		{"invalid port", func(v map[string]string) { v["APP_PORT"] = "70000" }},
		{"invalid duration", func(v map[string]string) { v["ACCESS_TOKEN_TTL"] = "15" }},
		{"zero attempts", func(v map[string]string) { v["MAX_FAILED_LOGIN_ATTEMPTS"] = "0" }},
		{"missing database", func(v map[string]string) { v["MYSQL_DATABASE"] = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := validValues()
			tt.mutate(values)

			if _, err := build(func(key string) string { return values[key] }); err == nil {
				t.Fatal("build returned nil error")
			}
		})
	}
}

func TestParseEnv(t *testing.T) {
	input := `
# comment
APP_ENV=test

export MYSQL_USER="app_user"
MYSQL_PASSWORD='secret'
EMPTY=
`
	values, err := parseEnv(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseEnv returned error: %v", err)
	}

	want := map[string]string{
		"APP_ENV":        "test",
		"MYSQL_USER":     "app_user",
		"MYSQL_PASSWORD": "secret",
		"EMPTY":          "",
	}
	for key, expected := range want {
		if values[key] != expected {
			t.Errorf("%s = %q, want %q", key, values[key], expected)
		}
	}
}

func TestParseEnvRejectsInvalidLine(t *testing.T) {
	if _, err := parseEnv(strings.NewReader("NO_EQUALS")); err == nil {
		t.Fatal("parseEnv returned nil error")
	}
}
