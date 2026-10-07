# Retain the pinned supplier's Node runtime and existing image exception.
FROM ghcr.io/zitadel/zitadel-login:v4.19.2@sha256:ee98f024ddbebce788a7faf5a4b5571d20cbddf3bca8d3923091c424f2855737
USER root
RUN rm -rf /app && mkdir /app && chown 1001:1001 /app
COPY --chown=1001:1001 .next/standalone/ /app/
USER 1001
