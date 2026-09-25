# Dynamic audit agent. The registry runs this image under gVisor (runsc) with
# --network=none, a read-only root, no capabilities and tight limits; see
# registry/internal/audit/docker.go.
FROM node:24-alpine

RUN apk add --no-cache tar gzip

COPY agent.js /opt/rivet/agent.js
COPY egress-hook.js /opt/rivet/egress-hook.js

USER node
ENTRYPOINT ["node", "/opt/rivet/agent.js"]
