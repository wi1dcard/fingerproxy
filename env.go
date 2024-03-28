package fingerproxy

import (
	"os"
	"strings"
)

func envWithDefault(key string, defaultVal string) string {
	if envVal, ok := os.LookupEnv(key); ok {
		return envVal
	}
	return defaultVal
}

func envWithDefaultBool(key string, defaultVal bool) bool {
	if envVal, ok := os.LookupEnv(key); ok {
		if strings.ToLower(envVal) == "true" {
			return true
		} else if strings.ToLower(envVal) == "false" {
			return false
		}
	}
	return defaultVal
}
