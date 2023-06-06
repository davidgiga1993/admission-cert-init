FROM alpine

WORKDIR /app
COPY bin/admission-cert-init ./
RUN chmod 555 /app/admission-cert-init
ENTRYPOINT ["/bin/sh", "-c", "/app/admission-cert-init"]

