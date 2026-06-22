FROM node:24-alpine

RUN apk add --no-cache tar gzip

COPY agent.js /usr/local/bin/rivet-audit-agent
RUN chmod +x /usr/local/bin/rivet-audit-agent

USER node
ENTRYPOINT ["node", "/usr/local/bin/rivet-audit-agent"]

