package app

import (
	"os"
	"strings"
)

type Config struct {
	NATSUser      string
	NATSPassword  string
	NATSEndpoints []string
	LocalEndpoint string
	LocalPort     string
}

var globalCfg Config

func initConfig() {
	globalCfg = Config{
		NATSEndpoints: strings.Split(os.Getenv("PROXY_ENDPOINTS"), ","),
		NATSUser:      os.Getenv("PROXY_USER"),
		NATSPassword:  os.Getenv("PROXY_PASSWORD"),
		LocalEndpoint: "localhost",
		LocalPort:     os.Getenv("LOCAL_PORT"),
	}
}

func GetConfig() *Config {
	return &globalCfg
}
