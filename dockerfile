FROM python:3.12-slim

RUN apt-get update && apt-get install -y curl unzip && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash scanner

RUN curl -fsSL https://steampipe.io/install/steampipe.sh | sh

RUN curl -fsSL -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && \
    chmod +x /usr/local/bin/opa

RUN pip install flask --break-system-packages

USER scanner
WORKDIR /home/scanner/openframp

RUN steampipe plugin install aws azure azuread github

RUN mkdir -p /home/scanner/.steampipe/config

RUN printf 'connection "aws" {\n  plugin  = "aws"\n  regions = ["us-west-2"]\n}\n' > /home/scanner/.steampipe/config/aws.spc

RUN printf 'connection "azure" {\n  plugin = "azure"\n  environment = "AZUREPUBLICCLOUD"\n}\n' > /home/scanner/.steampipe/config/azure.spc

RUN printf 'connection "azuread" {\n  plugin = "azuread"\n  environment = "AZUREPUBLICCLOUD"\n}\n' > /home/scanner/.steampipe/config/azuread.spc

RUN printf 'connection "github" {\n  plugin = "github"\n}\n' > /home/scanner/.steampipe/config/github.spc

COPY --chown=scanner:scanner catalog/ catalog/
COPY --chown=scanner:scanner oscal/ oscal/
COPY --chown=scanner:scanner checks/ checks/
COPY --chown=scanner:scanner web/ web/
COPY --chown=scanner:scanner scan.sh .
COPY --chown=scanner:scanner ssp-parser/ ssp-parser/

EXPOSE 4000

CMD ["./scan.sh"]