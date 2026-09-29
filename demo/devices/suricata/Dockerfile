# Suricata (IDS) and rsyslog from Alpine's own packages — built once, while online (start.sh), in the Containerlab
# distro's Docker engine. Nothing is downloaded at run time: no suricata-update, no rule feeds (local.rules only).
FROM alpine:3.20
RUN apk add --no-cache suricata rsyslog && suricata -V
