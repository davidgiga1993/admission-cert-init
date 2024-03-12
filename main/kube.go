package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	errors2 "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"strconv"
)

type KubeApi struct {
	kubeClient *kubernetes.Clientset
	ctx        context.Context
	namespace  string
}

func CreateKubeApi() KubeApi {
	kubeConfig := ctrl.GetConfigOrDie()
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		log.Panic(err)
	}

	namespace, err := getCurrentNamespace()
	if err != nil {
		log.Panic(err)
	}

	return KubeApi{
		kubeClient: kubeClient,
		namespace:  namespace,
		ctx:        context.Background(),
	}

}

func getCurrentNamespace() (string, error) {
	namespaceData, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	namespace := attribute("NAMESPACE", string(namespaceData))
	if namespace == "" {
		return "", fmt.Errorf("could not determin namespace %v", err)
	}
	return namespace, nil
}

func (k *KubeApi) GetSecret(name string) (*v1.Secret, error) {
	secret, err := k.kubeClient.CoreV1().Secrets(k.namespace).Get(k.ctx, name, metav1.GetOptions{})
	if err != nil {
		statusErr, ok := err.(*errors2.StatusError)
		if !ok {
			return nil, err
		}
		if statusErr.Status().Code == 404 {
			return nil, nil
		}
	}
	return secret, nil
}

func (k *KubeApi) CreateSecret(secret *v1.Secret) (*v1.Secret, error) {
	return k.kubeClient.CoreV1().Secrets(k.namespace).Create(k.ctx, secret, metav1.CreateOptions{})
}

func (k *KubeApi) UpdateSecret(secret *v1.Secret) (*v1.Secret, error) {
	return k.kubeClient.CoreV1().Secrets(k.namespace).Update(k.ctx, secret, metav1.UpdateOptions{})
}

// GetWebhookConfigCa returns the currently configured CA for the webhook (PEM encoded) or nil
// if no CA is configured
func (k *KubeApi) GetWebhookConfigCa(config Config) [][]byte {
	webhook, err := k.kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(k.ctx, config.WebhookName, metav1.GetOptions{})
	if err != nil {
		log.Panic(fmt.Errorf("could not get mutating webhook config %v: %v", config.WebhookName, err))
	}
	if len(webhook.Webhooks) == 0 {
		return nil
	}

	cas := make([][]byte, 0)
	for _, mutatingWebhook := range webhook.Webhooks {
		pem := mutatingWebhook.ClientConfig.CABundle
		if len(pem) > 0 {
			cas = append(cas, pem)
		}
	}
	if len(cas) == 0 {
		return nil
	}
	return cas
}

// PatchWebhookConfig Updates the caBundle of the webhook config
func (k *KubeApi) PatchWebhookConfig(config Config, caCert *bytes.Buffer) {
	patches := make([]JsonPatch, 0)
	webhook, err := k.kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(k.ctx, config.WebhookName, metav1.GetOptions{})
	if err != nil {
		log.Panic(fmt.Errorf("could not get mutating webhook config %v: %v", config.WebhookName, err))
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

	_, err = k.kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Patch(context.Background(), config.WebhookName,
		types.JSONPatchType,
		PatchToBytes(patches),
		metav1.PatchOptions{})
	if err != nil {
		panic(fmt.Errorf("could not patch mutating webhook config %v: %v", config.WebhookName, err))
	}
}
