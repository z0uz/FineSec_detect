FROM python:3.11-slim

WORKDIR /github/workspace

RUN pip install --no-cache-dir requests huggingface_hub

COPY action/entrypoint.py /entrypoint.py

ENTRYPOINT ["python", "/entrypoint.py"]
