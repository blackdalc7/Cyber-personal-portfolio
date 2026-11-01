# Velociraptor server for the lab. The release binary is pinned by URL *and* SHA-256 so a swapped
# download fails the build. Pick a release at https://github.com/Velocidex/velociraptor/releases,
# then: curl -sL "$URL" | sha256sum   and put both values in deploy/.env.
FROM debian:12-slim
ARG VELOCIRAPTOR_URL
ARG VELOCIRAPTOR_SHA256
RUN test -n "$VELOCIRAPTOR_URL" && test -n "$VELOCIRAPTOR_SHA256" \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
 && curl -fsSL -o /usr/local/bin/velociraptor "$VELOCIRAPTOR_URL" \
 && echo "$VELOCIRAPTOR_SHA256  /usr/local/bin/velociraptor" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/velociraptor \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10002 velo \
 && useradd --system --uid 10002 --gid 10002 --home-dir /velo --shell /usr/sbin/nologin velo \
 && mkdir -p /velo && chown velo:velo /velo
COPY --chmod=0755 entrypoint.sh /entrypoint.sh
USER velo
WORKDIR /velo
VOLUME ["/velo"]
EXPOSE 8000 8889
ENTRYPOINT ["/entrypoint.sh"]
