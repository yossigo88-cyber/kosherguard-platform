# KosherGuard PIR service image.
# STATUS: UNVERIFIED - this image has not been built here; the CI
# local-interop workflow (.github/workflows/pir-local-interop.yml)
# builds and exercises the same pinned sources directly. It is source
# integration with Apple's vetted PIR service, not a reimplementation:
# the private-query protocol runs in Apple's own binaries.
#
# Server: github.com/apple/pir-service-example (PIRService, Hummingbird
# + swift-homomorphic-encryption release/1.1, includes a Privacy Pass
# publicly-verifiable-token issuer). Apple's README warns the example
# "should not be run in production" - production readiness review is
# outstanding and tracked in docs/reviews.
#
# Tooling: PIRProcessDatabase is NOT a product of pir-service-example;
# it is a product of apple/swift-homomorphic-encryption and is built
# from that repository at the revision pinned by the service's
# Package.resolved (verified at build time below - a branch pin can
# move, so the build fails loudly on drift instead of silently using
# different sources).
FROM swift:6.1-jammy AS build-service

ARG PIR_SERVICE_COMMIT=bbb215355b87be40e081756d072f29cd8f9f000b
# Must equal the swift-homomorphic-encryption revision pinned in
# pir-service-example's Package.resolved at PIR_SERVICE_COMMIT.
ARG HE_REVISION=992cbe5a62938ca171e2e93a996c1e0d37f89a39
RUN git clone https://github.com/apple/pir-service-example /src \
    && cd /src && git checkout $PIR_SERVICE_COMMIT \
    && resolved=$(grep -A6 '"identity" : "swift-homomorphic-encryption"' Package.resolved \
        | sed -n 's/.*"revision" : "\([0-9a-f]\{40\}\)".*/\1/p') \
    && echo "Package.resolved pins swift-homomorphic-encryption at $resolved" \
    && test "$resolved" = "$HE_REVISION"
WORKDIR /src
RUN swift build -c release --product PIRService

FROM swift:6.1-jammy AS build-tools

ARG HE_REVISION=992cbe5a62938ca171e2e93a996c1e0d37f89a39
RUN git clone https://github.com/apple/swift-homomorphic-encryption /he \
    && cd /he && git checkout $HE_REVISION \
    && swift build -c release --product PIRProcessDatabase

FROM swift:6.1-jammy-slim
COPY --from=build-service /src/.build/release/PIRService /usr/local/bin/
COPY --from=build-tools /he/.build/release/PIRProcessDatabase /usr/local/bin/
COPY prepare-dataset.sh /usr/local/bin/prepare-dataset
# Dataset pipeline input: textpb exported by
# url-filter-server/app/pir_export.py (Apple keyword-PIR input format).
VOLUME ["/dataset", "/processed"]
ENTRYPOINT ["/usr/local/bin/PIRService"]
