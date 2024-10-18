package logger

import (
	"os"

	log "github.com/sirupsen/logrus"
)

func init() {
	lvl, ok := os.LookupEnv("LOG_LEVEL")
	if !ok {
		lvl = "info"
	}

	ll, err := log.ParseLevel(lvl)
	if err != nil {
		ll = log.DebugLevel
	}

	log.SetLevel(ll)
}

func SetLoggerFormat(logFormat string) {

	switch logFormat {
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	}
}
