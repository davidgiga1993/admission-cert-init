package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	log "github.com/sirupsen/logrus"
	"time"
)

func main() {
	config := LoadConfig()
	kubeApi := CreateKubeApi()
	certMagic := CreateCertMagic(config)
	certIo := CreateCertIo(config, kubeApi)

	certs, err := certIo.GetCurrentCerts()
	if err != nil {
		log.Panic(err)
	}

	var caPrivateKey *rsa.PrivateKey
	var caPublicKey *x509.Certificate

	var privateKey *rsa.PrivateKey
	var publicKey *x509.Certificate
	didUpdateCertificate := false

	if certs != nil {
		caPrivateKey = certs.ca.privateKey
		caPublicKey = certs.ca.publicKey
		publicKey = certs.cert.publicKey
	}
	if caPublicKey == nil || !isValid(caPublicKey, "CA") {
		log.Info("renewing ca...")
		caPrivateKey, caPublicKey, err = certMagic.GenerateRootCa()
		didUpdateCertificate = true
		if err != nil {
			log.Panic(err)
		}
	}

	if didUpdateCertificate || publicKey == nil || !isValid(publicKey, "Cert") {
		log.Info("renewing certificate...")
		privateKey, publicKey, err = certMagic.CreateCertificate(caPublicKey, caPrivateKey)
		didUpdateCertificate = true
		if err != nil {
			log.Panic(err)
		}
	}

	// Make sure the webhook config matches
	configuredCas := kubeApi.GetWebhookConfigCa(config)
	if !didUpdateCertificate && IsDifferentCa(configuredCas, caPublicKey) {
		log.Info("webhook ca didn't match secret - updating webhook...")
		kubeApi.PatchWebhookConfig(config, toCertificatePem(caPublicKey.Raw))
	}

	if !didUpdateCertificate {
		log.Info("no certificate update required")
		return
	}

	err = certIo.WriteCertificates(&CertCollection{
		ca: &CertBundle{
			privateKey: caPrivateKey,
			publicKey:  caPublicKey,
		},
		cert: &CertBundle{
			privateKey: privateKey,
			publicKey:  publicKey,
		},
	})
	if err != nil {
		log.Panic(err)
	}

	kubeApi.PatchWebhookConfig(config, toCertificatePem(caPublicKey.Raw))
}

// IsDifferentCa compares the given buffers and return true if both are not equal
func IsDifferentCa(current [][]byte, expected *x509.Certificate) bool {
	if current == nil {
		return true
	}
	for _, pem := range current {
		ca, err := pemToCertificate(pem)
		if err != nil {
			log.Warnf("could not parse pem %v", err)
			continue
		}
		if !bytes.Equal(ca.Raw, expected.Raw) {
			return true
		}
	}
	return false
}

func isValid(key *x509.Certificate, logTag string) bool {
	gracePeriod, _ := time.ParseDuration("720h")
	threshold := time.Now().Add(gracePeriod)
	valid := key.NotAfter.After(threshold)
	log.Infof("%s certificate is valid: %v (%v)", logTag, valid, key.NotAfter)
	return valid
}
