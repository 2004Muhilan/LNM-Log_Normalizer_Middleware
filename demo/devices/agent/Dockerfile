# The lab agent (lab equipment, not ULPF): lab.sh behind HTTP. Build context: demo/devices.
#   docker build -t ulpf-lab-agent -f demo/devices/agent/Dockerfile demo/devices
FROM alpine:3.20
RUN apk add --no-cache bash openssh-client docker-cli python3 procps
COPY lab.sh /lab/lab.sh
COPY agent/agent.py /lab/agent.py
ENTRYPOINT ["python3", "/lab/agent.py"]
