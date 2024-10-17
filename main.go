// main.go
package main

import (
	"github.com/unicrons/powerpipe-securityhub-importer/cmd"
	"github.com/unicrons/powerpipe-securityhub-importer/pkg/aws"
	"github.com/unicrons/powerpipe-securityhub-importer/pkg/logger"

	log "github.com/sirupsen/logrus"
)

func main() {

	flags, err := cmd.ParseFlags()
	if err != nil {
		log.Error("error parsing flags:", err)
		return
	}

	roleName := flags.RoleName
	findingsPath := flags.FindingsFile
	sessionName := flags.SessionName
	onlyFailed := flags.OnlyFailed
	logFormat := flags.LogFormat

	logger.SetLoggerFormat(logFormat)

	log.Info("starting powerpipe securityhub importer")

	err = aws.SecurityHubImportFindings(findingsPath, roleName, sessionName, onlyFailed)
	if err != nil {
		log.Error("error importing security findings:", err)
		return
	}

	log.Info("securityhub finding import finished")
}
