package cmd

import (
	"flag"
	"fmt"
)

type CmdFlags struct {
	RoleName     string
	FindingsFile string
	SessionName  string
	LogFormat    string
	OnlyFailed   bool
}

func ParseFlags() (*CmdFlags, error) {
	flags := CmdFlags{}

	flag.StringVar(&flags.RoleName, "role", "", "AWS assume role name")
	flag.StringVar(&flags.SessionName, "session", "powerpipe-securityhub-importer", "AWS assume role session name")
	flag.StringVar(&flags.FindingsFile, "findings", "", "SecurityHub asff json file path")
	flag.StringVar(&flags.LogFormat, "log", "default", "Log format: default, json")
	flag.BoolVar(&flags.OnlyFailed, "failed", false, "Skip Importing PASSED & NOT_AVAILABLE findings")
	flag.Parse()

	if flags.RoleName == "" {
		flag.Usage()
		return nil, fmt.Errorf("-role flag is required")
	}

	if flags.FindingsFile == "" {
		flag.Usage()
		return nil, fmt.Errorf("-path flag is required")
	}

	if flags.LogFormat != "default" && flags.LogFormat != "json" {
		flag.Usage()
		return nil, fmt.Errorf("-log unknown value. Valid values are: default, json")
	}

	return &flags, nil
}
