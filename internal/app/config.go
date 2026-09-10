package app

import (
	"os"
	"strconv"
)

// Config is the full set of settings the composition root needs. Load reads it
// from the environment; a cmd/ binary may build one by hand instead (e.g. in
// tests).
type Config struct {
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string

	RedisAddr     string
	RedisPassword string
	RedisDB       int

	RSAPrivateKeyPath string
	RSAPublicKeyPath  string

	HTTPAddr     string
	CookieSecure bool
	LoginURL     string
}

// Load builds a Config from environment variables, applying defaults.
func Load() Config {
	return Config{
		DBHost:     env("DB_HOST", "localhost"),
		DBPort:     envInt("DB_PORT", 3306),
		DBUser:     env("DB_USER", "iam"),
		DBPassword: env("DB_PASSWORD", "secret"),
		DBName:     env("DB_NAME", "iam_db"),

		RedisAddr:     env("REDIS_ADDR", "localhost:6379"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),
		RedisDB:       envInt("REDIS_DB", 0),

		RSAPrivateKeyPath: env("RSA_PRIVATE_KEY", ".rsa/private.pem"),
		RSAPublicKeyPath:  env("RSA_PUBLIC_KEY", ".rsa/public.pem"),

		HTTPAddr:     ":" + env("PORT", "8080"),
		CookieSecure: env("COOKIE_SECURE", "true") == "true",
		LoginURL:     env("LOGIN_URL", "/login"),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return v
	}
	return def
}
