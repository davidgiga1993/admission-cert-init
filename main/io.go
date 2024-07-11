package main

import (
	"bytes"
	"fmt"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
)

type CertIo struct {
	config Config
	api    KubeApi
}

func CreateCertIo(config Config, api KubeApi) CertIo {
	return CertIo{
		config: config,
		api:    api,
	}
}

func (c CertIo) GetCurrentCerts() (*CertCollection, error) {
	if c.config.Mode == ModeFile {
		collection := CertCollection{
			ca:   nil,
			cert: nil,
		}
		ca, err := c.readCertificateFromFiles(c.config.CaOutput)
		if err != nil {
			return nil, err
		}
		collection.ca = ca

		cert, err := c.readCertificateFromFiles(c.config.CertOutput)
		if err != nil {
			return nil, err
		}
		collection.cert = cert
		if ca == nil || cert == nil {
			return nil, nil
		}
		return &collection, nil
	}
	if c.config.Mode == ModeSecret {
		return c.readCertificatesFromSecret()
	}
	return nil, fmt.Errorf("invalid mode %v", c.config.Mode)
}

func (c CertIo) WriteCertificates(certs *CertCollection) error {
	if c.config.Mode == ModeFile {
		err := c.writeCertificatePairFile(certs.ca, c.config.CaOutput)
		if err != nil {
			return err
		}
		err = c.writeCertificatePairFile(certs.cert, c.config.CertOutput)
		if err != nil {
			return err
		}
		return nil
	}
	if c.config.Mode == ModeSecret {
		return c.writeCertsToSecret(certs)
	}
	return fmt.Errorf("invalid mode %v", c.config.Mode)
}

func (c CertIo) readCertificatesFromSecret() (*CertCollection, error) {
	secret, err := c.api.GetSecret(c.config.SecretName)
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, nil
	}

	collection := CertCollection{
		ca:   nil,
		cert: nil,
	}
	ca, err := c.readCertificateFromSecret(secret, c.config.SecretCaName)
	if err != nil || ca == nil {
		return nil, err
	}
	collection.ca = ca

	cert, err := c.readCertificateFromSecret(secret, c.config.SecretCertName)
	if err != nil || cert == nil {
		return nil, err
	}
	collection.cert = cert
	return &collection, nil
}

func (c CertIo) writeCertsToSecret(certs *CertCollection) error {
	secret, err := c.api.GetSecret(c.config.SecretName)
	if err != nil {
		return err
	}
	createNewSecret := secret == nil
	if createNewSecret {
		// Create new
		secret = &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      c.config.SecretName,
				Namespace: c.api.namespace,
			},
			Data: make(map[string][]byte),
		}
	}
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}

	c.updateSecretCertificatePair(secret, certs.ca, c.config.SecretCaName)
	c.updateSecretCertificatePair(secret, certs.cert, c.config.SecretCertName)

	if createNewSecret {
		secret, err = c.api.CreateSecret(secret)
		if err != nil {
			return fmt.Errorf("could not create secret: %v", err)
		}
	} else {
		secret, err = c.api.UpdateSecret(secret)
		if err != nil {
			return fmt.Errorf("could not update secret: %v", err)
		}
	}
	return nil
}

func (c CertIo) updateSecretCertificatePair(secret *v1.Secret, bundle *CertBundle, keyPrefix string) {
	secret.Data[keyPrefix+".pem"] = toCertificatePem(bundle.publicKey.Raw).Bytes()
	secret.Data[keyPrefix+".key"] = toPrivateKeyPem(bundle.privateKey).Bytes()
}

func (c CertIo) readCertificateFromSecret(secret *v1.Secret, keyPrefix string) (*CertBundle, error) {
	publicKeyData := secret.Data[keyPrefix+".pem"]
	privateKeyData := secret.Data[keyPrefix+".key"]
	if publicKeyData == nil || privateKeyData == nil {
		return nil, nil
	}

	publicKey, err := pemToCertificate(publicKeyData)
	if err != nil {
		return nil, err
	}
	privateKey, err := pemToPrivateKey(privateKeyData)
	if err != nil {
		return nil, err
	}

	return &CertBundle{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func (c CertIo) writeCertificatePairFile(bundle *CertBundle, output string) error {
	err := writeFile(output+".pem", toCertificatePem(bundle.publicKey.Raw))
	if err != nil {
		return err
	}

	err = writeFile(output+".key", toPrivateKeyPem(bundle.privateKey))
	if err != nil {
		return err
	}
	return nil
}

func (c CertIo) readCertificateFromFiles(output string) (*CertBundle, error) {
	certData, err := os.ReadFile(output + ".pem")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	publicKey, err := pemToCertificate(certData)
	if err != nil {
		return nil, err
	}

	keyData, err := os.ReadFile(output + ".key")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	key, err := pemToPrivateKey(keyData)
	if err != nil {
		return nil, err
	}

	return &CertBundle{
		privateKey: key,
		publicKey:  publicKey,
	}, nil
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
