package config

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	RegistryURL      string
	HtpasswdPath     string
	WebUIPort        string
	SessionSecret    string
	RegistryUsername string
	RegistryPassword string
	TokenIssuer      string
	TokenExpiration  int
	TokenKeyPath     string
	ACLPath          string
}

func Load() *Config {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	cfg := &Config{
		RegistryURL:      getEnv("REGISTRY_URL", "http://localhost:5000"),
		HtpasswdPath:     getEnv("REGISTRY_AUTH_HTPASSWD_PATH", "/auth/registry.password"),
		WebUIPort:        getEnv("WEB_UI_PORT", "8080"),
		SessionSecret:    getEnv("SESSION_SECRET", "default-secret-change-me"),
		RegistryUsername: getEnv("REGISTRY_USERNAME", ""),
		RegistryPassword: getEnv("REGISTRY_PASSWORD", ""),
		TokenIssuer:      getEnv("TOKEN_ISSUER", "registry-token-issuer"),
		TokenExpiration:  getEnvInt("TOKEN_EXPIRATION", 900), // 15 minutes default
		TokenKeyPath:     getEnv("TOKEN_KEY_PATH", "/auth/token.key"),
		ACLPath:          getEnv("ACL_PATH", "/auth/acl.json"),
	}

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		var intValue int
		if _, err := fmt.Sscanf(value, "%d", &intValue); err == nil {
			return intValue
		}
	}
	return defaultValue
}
