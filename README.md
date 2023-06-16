# Admission Webhook Certificate Init Container
This container creates a self-signed certificate and updates the `MutatingWebhookConfigurations` with the 
new CA.

The intended use case is to use it as an init container for your custom admission hooks and
never to worry about certificates.


## Configuration
There are two modes of operation:

### File based
This will write the private key into a file. If a cert does already exist
at that location, the expiry time is validated. If it's < 7 days it will be replaced.

### Secret based
Same as file based but uses a kubernetes secret instead as storage.

```yaml
      initContainers:
        - name: "cert-init"
          image: ghcr.io/davidgiga1993/admission-cert-init:latest
          env:
            - name: SUBJECT_ORGANIZATION
              value: your-company.com
            - name: DNS_NAMES
              value: name-of-webhook-service.my-namespace.svc
            - name: COMMON_NAME
              value: name-of-webhook-service.my-namespace.svc
            - name: WEBHOOK_NAME
              value: name-of-webhook-to-be-updated

            - name: MODE
              value: file # file or secret

            - name: CERT_OUTPUT # Only required for file mode
              value: /certs/cert # Creates cert.pem and cert.key
            - name: CA_OUTPUT # Only required for file mode
              value: /certs/ca # Creates ca.pem and ca.key

            - name: SECRET_NAME # Only required for secret mode
              value: webhook-cert # Name of the secret in the current namespace
            - name: SECRET_CERT_NAME # Only required for secret mode
              value: cert # Name of the secret's key for storing the server cert
            - name: SECRET_CA_NAME # Only required for secret mode
              value: ca # Name of the secret's key for storing the CA cert

          volumeMounts:
            - mountPath: /certs
              name: webhook-certs
```