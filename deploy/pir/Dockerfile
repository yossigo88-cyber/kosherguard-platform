# KosherGuard PIR service image.
# STATUS: UNVERIFIED - no Swift toolchain exists in this build
# environment, so this Dockerfile has never been built. It is source
# integration with Apple's vetted PIR service, not a reimplementation:
# the private-query protocol runs in Apple's own binary.
#
# Server: github.com/apple/pir-service-example (PIRService, Hummingbird
# + swift-homomorphic-encryption release/1.1, includes a Privacy Pass
# publicly-verifiable-token issuer). Apple's README warns the example
# "should not be run in production" - production readiness review is
# outstanding and tracked in docs/reviews.
FROM swift:6.1-jammy AS build

ARG PIR_SERVICE_COMMIT=bbb215355b87be40e081756d072f29cd8f9f000b
RUN git clone https://github.com/apple/pir-service-example /src \
    && cd /src && git checkout $PIR_SERVICE_COMMIT
WORKDIR /src
RUN swift build -c release --product PIRService \
    && swift build -c release --product PIRProcessDatabase \
    && swift build -c release --product PIRShardDatabase

FROM swift:6.1-jammy-slim
COPY --from=build /src/.build/release/PIRService /usr/local/bin/
COPY --from=build /src/.build/release/PIRProcessDatabase /usr/local/bin/
COPY --from=build /src/.build/release/PIRShardDatabase /usr/local/bin/
COPY prepare-dataset.sh /usr/local/bin/prepare-dataset
# Dataset pipeline input: textpb exported by
# url-filter-server/app/pir_export.py (Apple keyword-PIR input format).
VOLUME ["/dataset", "/processed"]
ENTRYPOINT ["/usr/local/bin/PIRService"]
