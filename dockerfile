FROM python:3.14-slim

# Install dependencies
RUN apt-get update && apt-get install -y curl unzip && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash scanner

# Install Steampipe
RUN curl -fsSL https://steampipe.io/install/steampipe.sh | sh

# Install OPA
RUN curl -fsSL -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && \
    chmod +x /usr/local/bin/opa

# Switch to non-root user
USER scanner
WORKDIR /home/scanner/openframp

# Install AWS plugin as non-root
RUN steampipe plugin install aws

# Default Steampipe config
RUN mkdir -p /home/scanner/.steampipe/config && \
    printf 'connection "aws" {\n  plugin  = "aws"\n  regions = ["us-west-2"]\n}\n' > /home/scanner/.steampipe/config/aws.spc

# Copy project files
COPY --chown=scanner:scanner checks/ checks/
COPY --chown=scanner:scanner oscal/ oscal/
COPY --chown=scanner:scanner scan.sh .

ENTRYPOINT ["./scan.sh"]