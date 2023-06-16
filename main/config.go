package main

import (
	"os"
	"strings"
)

const ModeFile = "file"
const ModeSecret = "secret"

type Config struct {
	SubjectOrg  string
	CommonName  string
	DnsNames    []string
	WebhookName string

	Mode string
	// File stuff
	CaOutput   string
	CertOutput string
	// Secerts stuff
	SecretName     string
	SecretCertName string
	SecretCaName   string
}

func LoadConfig() Config {
	dnsNamesStr := attribute("DNS_NAMES", "webhook-service,webhook-service.default,webhook-service.default.svc")

	return Config{
		SubjectOrg:  attribute("SUBJECT_ORGANIZATION", "company.com"),
		CommonName:  attribute("COMMON_NAME", "webhook-service.default.svc"),
		DnsNames:    strings.Split(dnsNamesStr, ","),
		WebhookName: attribute("WEBHOOK_NAME", "my-webhook"),

		Mode:       attribute("MODE", "file"),
		CaOutput:   attribute("CA_OUTPUT", "/certs/ca"),
		CertOutput: attribute("CERT_OUTPUT", "/certs/cert"),

		SecretName:     attribute("SECRET_NAME", "webhook-cert"),
		SecretCertName: attribute("SECRET_CERT_NAME", "cert"),
		SecretCaName:   attribute("SECRET_CA_NAME", "ca"),
	}
}

func attribute(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
