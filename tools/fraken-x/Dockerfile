# Build: docker build -t fraken -f tools/fraken/Dockerfile .
# Run: docker run -ti fraken fraken -rules /opt/signature-base -folder /
# Image: us-docker.pkg.dev/osdfir-registry/turbinia/release/fraken:latest

FROM rust:alpine AS fraken-builder

WORKDIR /app

RUN apk add --no-cache musl-dev

COPY . .

RUN cargo build --release

FROM alpine:3.18.4 AS fraken
# Install yara rules and fraken binary.
RUN apk add --no-cache -t .build-deps git
RUN cd /opt \
    && git clone https://github.com/Neo23x0/signature-base.git \
    && find /opt/signature-base -type f -not -iname '*.yar' -not -iname '*.yara' -not -iname 'file-type-signatures.txt' -delete

COPY --from=fraken-builder /app/target/release/fraken-x /bin/fraken
CMD ["fraken","-h"]
