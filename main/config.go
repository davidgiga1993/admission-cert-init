package main

import (
	"os"
	"strings"
)

type Config struct {
	SubjectOrg  string
	CommonName  string
	DnsNames    []string
	KeyOutput   string
	CertOutput  string
	WebhookName string
}

func LoadConfig() Config {
	dnsNamesStr := attribute("DNS_NAMES", "webhook-service,webhook-service.default,webhook-service.default.svc")

	return Config{
		SubjectOrg:  attribute("SUBJECT_ORGANIZATION", "company.com"),
		CommonName:  attribute("COMMON_NAME", "webhook-service.default.svc"),
		DnsNames:    strings.Split(dnsNamesStr, ","),
		KeyOutput:   attribute("KEY_OUTPUT", "/certs/key.pem"),
		CertOutput:  attribute("CERT_OUTPUT", "/certs/cert.epm"),
		WebhookName: attribute("WEBHOOK_NAME", "my-webhook"),
	}
}

func attribute(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
