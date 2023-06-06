package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"math/big"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"strconv"
	"time"
)

func main() {
	config := LoadConfig()

	var caPEM, serverCertPEM, serverPrivKeyPEM *bytes.Buffer
	// CA config
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization: []string{config.SubjectOrg},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// CA private key
	caPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	// Self-signed CA certificate
	caBytes, err := x509.CreateCertificate(cryptorand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// PEM encode CA cert
	caPEM = new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	// server cert config
	cert := &x509.Certificate{
		DNSNames:     config.DnsNames,
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:   config.CommonName,
			Organization: []string{config.SubjectOrg},
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
		fmt.Println(err)
	}

	// sign the server cert
	serverCertBytes, err := x509.CreateCertificate(cryptorand.Reader, cert, ca, &serverPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	// PEM encode the  server cert and key
	serverCertPEM = new(bytes.Buffer)
	_ = pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	})

	serverPrivKeyPEM = new(bytes.Buffer)
	_ = pem.Encode(serverPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})

	err = writeFile(config.CertOutput, serverCertPEM)
	if err != nil {
		log.Panic(err)
	}

	err = writeFile(config.KeyOutput, serverPrivKeyPEM)
	if err != nil {
		log.Panic(err)
	}

	patchWebhookConfig(config, caPEM)
}

// patchWebhookConfig Updates the caBundle of the webhook config
func patchWebhookConfig(config Config, caCert *bytes.Buffer) {
	kubeConfig := ctrl.GetConfigOrDie()
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		panic(err)
	}

	patches := make([]JsonPatch, 0)
	webhook, err := kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), config.WebhookName, metav1.GetOptions{})
	if err != nil {
		panic(fmt.Errorf("could not get mutating webhook config %v: %v", config.WebhookName, err))
	}

	base64Cert := base64.StdEncoding.EncodeToString(caCert.Bytes())
	for index, mutatingWebhook := range webhook.Webhooks {
		if mutatingWebhook.ClientConfig.CABundle == nil {
			patches = append(patches, JsonPatch{
				Operation: "add",
				Path:      "/webhooks/" + strconv.Itoa(index) + "/clientConfig/caBundle",
				Value:     base64Cert,
			})
			continue
		}
		patches = append(patches, JsonPatch{
			Operation: "replace",
			Path:      "/webhooks/" + strconv.Itoa(index) + "/clientConfig/caBundle",
			Value:     base64Cert,
		})
	}

	_, err = kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(context.Background(), config.WebhookName,
		types.JSONPatchType,
		PatchToBytes(patches),
		metav1.PatchOptions{})
	panic(fmt.Errorf("could not patch mutating webhook config %v: %v", config.WebhookName, err))
}

func writeFile(filepath string, data *bytes.Buffer) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data.Bytes())
	if err != nil {
		return err
	}
	return nil
}
