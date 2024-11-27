package fingerproxy

import (
	"log"
	"os"
	"strconv"
	"strings"
)

func envWithDefault(key string, defaultVal string) string {
	if envVal, ok := os.LookupEnv(key); ok {
		return envVal
	}
	return defaultVal
}

func envWithDefaultUint(key string, defaultVal uint) uint {
	if envVal, ok := os.LookupEnv(key); ok {
		if ret, err := strconv.ParseUint(envVal, 10, 0); err == nil {
			return uint(ret)
		} else {
			log.Fatalf("invalid environment variable $%s, expect uint, actual %s: %s", key, envVal, err)
		}
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
