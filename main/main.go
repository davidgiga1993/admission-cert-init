package main

import (
	"crypto/rsa"
	"crypto/x509"
	log "github.com/sirupsen/logrus"
	"time"
)

func main() {
	config := LoadConfig()
	kubeApi := CreateKubeApi(config)
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
	if caPublicKey == nil || !isValid(caPublicKey) {
		caPrivateKey, caPublicKey, err = certMagic.GenerateRootCa()
		didUpdateCertificate = true
		if err != nil {
			log.Panic(err)
		}
	}

	if didUpdateCertificate || publicKey == nil || !isValid(publicKey) {
		privateKey, publicKey, err = certMagic.CreateCertificate(caPublicKey, caPrivateKey)
		didUpdateCertificate = true
		if err != nil {
			log.Panic(err)
		}
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

func isValid(key *x509.Certificate) bool {
	gracePeriod, _ := time.ParseDuration("720h")
	return key.NotAfter.After(time.Now().Add(gracePeriod))
}
