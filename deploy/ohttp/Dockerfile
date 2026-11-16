# KosherGuard OHTTP gateway image.
# Builds the PINNED third-party gateway (deploy/ohttp/PINNED); no
# KosherGuard code and no OHTTP cryptography lives in this repository.
# OHTTP_KEY_SEED is injected at RUN TIME from the secret store - never
# baked into the image, never committed. This image has never been
# built or deployed; see README.md for the honest status.
FROM node:26-alpine
ARG OHTTP_GATEWAY_COMMIT=b071b966ba75379230355b8ce6a74a300fb8bbd9
WORKDIR /app
RUN wget -qO /tmp/gw.tar.gz \
      "https://codeload.github.com/thibmeu/ohttp-gateway/tar.gz/${OHTTP_GATEWAY_COMMIT}" \
    && tar xzf /tmp/gw.tar.gz --strip-components=1 \
    && rm /tmp/gw.tar.gz \
    && npm ci --omit=dev
ENV PORT=3000
EXPOSE 3000
# Required at runtime: OHTTP_KEY_SEED (secret store), TARGET_URL (PIR service).
CMD ["node", "--experimental-strip-types", "src/server.ts"]
