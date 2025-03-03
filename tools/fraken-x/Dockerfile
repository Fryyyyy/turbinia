# Build: docker build -t fraken -f tools/fraken/Dockerfile .
# Run: docker run -v /:/mnt/ -ti fraken fraken --magic /opt/rules/signature-base/misc/file-type-signatures.txt --folder /mnt/ /opt/rules/ 
# Image: us-docker.pkg.dev/osdfir-registry/turbinia/release/fraken:latest

FROM rust:alpine AS fraken-builder

WORKDIR /app

RUN apk add --no-cache musl-dev

COPY . .

RUN cargo build --release

FROM alpine:3.18.4 AS fraken
# Install yara rules and fraken binary.
RUN apk add --no-cache -t .build-deps git
RUN mkdir -p /opt/rules/
RUN cd /opt/rules \
    && git clone https://github.com/Neo23x0/signature-base.git
RUN cd /opt/rules \
    && git clone https://github.com/elastic/protections-artifacts.git
RUN find /opt/rules -type f -not -iname '*.yar' -not -iname '*.yara' -not -iname 'file-type-signatures.txt' -delete

COPY --from=fraken-builder /app/target/release/fraken-x /bin/fraken
CMD ["fraken","-h"]
