FROM public.ecr.aws/unocha/debian-snap-base:22-debian AS builder

WORKDIR /srv/src
COPY . .

ENV NODE_ENV=production
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

RUN cd app && \
    npm install

# The base image to build our app into. this already contains fonts and utilities.
FROM public.ecr.aws/unocha/debian-snap-base:22-debian

# Configure the service container.
ENV NODE_APP_DIR=/srv/www \
    PORT=8448 \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

RUN \
    # Install Chrome, so it can match. The base image already has the repo.
    apt-get update && \
    apt-get -qy dist-upgrade && \
    # For x86_64
    # apt-get -qy install --no-install-recommends google-chrome-stable && \
    # For aarch64 *and* x86_64
    apt-get -qy install --no-install-recommends chromium coreutils xvfb && \
    # Ok, cleanup!
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/*

# Set the workdir for node.
WORKDIR "${NODE_APP_DIR}"

# Install the app.
COPY --from=builder /srv/src/app/ /srv/www/

# Open the trench coat at the correct button.
EXPOSE ${PORT}
