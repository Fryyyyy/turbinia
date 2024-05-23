# Build: docker build -t fraken -f tools/fraken/Dockerfile .
# Run: docker run -ti fraken fraken -rules /opt/signature-base -folder /
# Image: us-docker.pkg.dev/osdfir-registry/turbinia/release/fraken:latest

FROM golang:alpine AS fraken-builder
RUN apk add --no-cache -t .build-deps \
  autoconf \
  automake \
  bison \
  build-base \
  curl \
  file \
  file-dev \
  flex \
  git \
  jansson \
  jansson-dev \
  jansson-static \
  libc-dev \
  libmagic \
  libmagic-static \
  libtool \
  linux-headers \
  openssl \
  openssl-dev \
  openssl-libs-static \
  py3-setuptools \
  python3 \
  python3-dev \
  rustup \
  sudo

RUN set -x \
  && echo "Compiling Yara from source..."

# Fetch and compile libyara
RUN mkdir -p /opt/fraken
WORKDIR /opt/fraken
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /tmp/rustup.sh
RUN sh /tmp/rustup.sh -y
RUN $HOME/.cargo/bin/rustup toolchain install stable --profile minimal --no-self-update
RUN $HOME/.cargo/bin/cargo install cargo-c 
RUN cd /opt/fraken && git clone https://github.com/VirusTotal/yara-x.git
RUN cd yara-x
WORKDIR /opt/fraken/yara-x 
RUN sudo $HOME/.cargo/bin/cargo cinstall -p yara-x-capi --release

# Compile fraken statically
COPY * /opt/fraken/
# RUN cd /opt/fraken && GOOS=linux GOARCH=amd64 go build -a -v -ldflags="-linkmode=external -extldflags=-static" -installsuffix netgo -tags yara_static,osusergo,netgo -o fraken
RUN cd /opt/fraken && GOOS=linux GOARCH=amd64 go build

FROM alpine:3.18.4 AS fraken
# Install yara rules and fraken binary.
RUN apk add --no-cache -t .build-deps git
RUN cd /opt \
    && git clone https://github.com/Neo23x0/signature-base.git \
    && find /opt/signature-base -type f -not -iname '*.yar' -not -iname '*.yara' -not -iname 'file-type-signatures.txt' -delete
COPY turbinia/config/rules/*.yar /opt/signature-base/yara/
#
COPY --from=fraken-builder /opt/fraken/fraken /bin/fraken
CMD ["fraken","-h"]
