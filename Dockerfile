FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

ARG AGENT_VERSION=unknown
ENV KAYA_AGENT_VERSION=${AGENT_VERSION}

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py protocol_v2.py ./

CMD ["python", "agent.py"]
