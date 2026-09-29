# Dynamic audit agent. The registry runs this image under gVisor (runsc) with
# --network=none, a read-only root, limited supervisor capabilities and tight
# limits. Package probes drop UID, groups and effective capabilities; see
# registry/internal/audit/docker.go.
FROM node:24-alpine

RUN apk add --no-cache tar gzip util-linux

COPY --chmod=700 agent.js /opt/rivet/agent.js
COPY egress-hook.js /opt/rivet/egress-hook.js
RUN chmod 755 /opt/rivet

USER root
ENTRYPOINT ["node", "/opt/rivet/agent.js"]
