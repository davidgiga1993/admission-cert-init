package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type CertBundle struct {
	privateKey *rsa.PrivateKey
	publicKey  *x509.Certificate
}
type CertCollection struct {
	ca   *CertBundle
	cert *CertBundle
}

type CertMagic struct {
	config Config
}

func CreateCertMagic(config Config) CertMagic {
	return CertMagic{
		config: config,
	}
}

func (c CertMagic) GenerateRootCa() (*rsa.PrivateKey, *x509.Certificate, error) {
	caPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// Self-signed CA certificate
	caConfig := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization: []string{c.config.SubjectOrg},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(cryptorand.Reader, caConfig, caConfig, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}
	caConfig.Raw = caBytes
	return caPrivKey, caConfig, nil
}

func (c CertMagic) CreateCertificate(caPrivKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate, error) {
	cert := &x509.Certificate{
		DNSNames:     c.config.DnsNames,
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:   c.config.CommonName,
			Organization: []string{c.config.SubjectOrg},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// server private key
	serverPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// sign the server cert
	serverCertBytes, err := x509.CreateCertificate(cryptorand.Reader, cert, cert, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	cert.Raw = serverCertBytes
	return serverPrivKey, cert, nil
}

func toPrivateKeyPem(key *rsa.PrivateKey) *bytes.Buffer {
	serverPrivKeyPEM := new(bytes.Buffer)
	_ = pem.Encode(serverPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return serverPrivKeyPEM
}

func toCertificatePem(publicKey []byte) *bytes.Buffer {
	serverCertPEM := new(bytes.Buffer)
	_ = pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: publicKey,
	})
	return serverCertPEM
}

func pemToCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no pem block found")
	}

	publicCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return publicCert, nil
}

func pemToPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no pem block found")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
