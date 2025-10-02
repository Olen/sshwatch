FROM fedora:42

# Install journalctl and Python
RUN dnf -y install systemd-udev systemd --nodocs && \
    dnf -y install python3 && \
    dnf clean all

# make Python write to stdout/stderr immediately
ENV PYTHONUNBUFFERED=1 PYTHONIOENCODING=UTF-8

# Add script
WORKDIR /app
COPY sshwatch.py /app/sshwatch.py
RUN chmod +x /app/sshwatch.py

# Default state path under /data
VOLUME ["/data"]

# Run as root to read the journal mounts
ENTRYPOINT ["python3", "-u", "/app/sshwatch.py"]
CMD ["--state", "/data/state.json", "--bootstrap", "7d", "--unit", "sshd.service"]

