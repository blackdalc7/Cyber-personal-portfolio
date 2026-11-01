# Optional prebuilt image for the Atomic runner (the Deployment can also bootstrap from the stock image).
#   docker build -t atomic-runner:lab --build-arg ART_REF=<tag-or-commit> . && microk8s images import < image.tar
FROM mcr.microsoft.com/powershell:7.5-ubuntu-24.04
ARG ART_REF=master
ARG IART_VERSION=2.2.0
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip procps sudo \
 && rm -rf /var/lib/apt/lists/* \
 && pwsh -NoProfile -Command "Set-PSRepository PSGallery -InstallationPolicy Trusted; \
      Install-Module invoke-atomicredteam -RequiredVersion ${IART_VERSION} -Scope AllUsers -Force; \
      Install-Module powershell-yaml -Scope AllUsers -Force" \
 && curl -fsSL -o /tmp/art.zip "https://github.com/redcanaryco/atomic-red-team/archive/${ART_REF}.zip" \
 && unzip -q /tmp/art.zip -d /tmp && mkdir -p /opt/AtomicRedTeam \
 && mv /tmp/atomic-red-team-*/atomics /opt/AtomicRedTeam/atomics && rm -rf /tmp/art.zip /tmp/atomic-red-team-*
ENV ATOMICS=/opt/AtomicRedTeam/atomics
CMD ["sleep", "infinity"]
