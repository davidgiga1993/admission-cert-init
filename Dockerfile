FROM alpine

WORKDIR /app
COPY bin/admission-cert-init ./
RUN chmod u+x /app/admission-cert-init
ENTRYPOINT ["/bin/sh", "-c", "/app/admission-cert-init"]

