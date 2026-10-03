FROM python:3.13-slim
WORKDIR /app

# INSTALL_NER=false builds a light image without the HerBERT PII model
# (redaction then uses the deterministic rules only).
ARG INSTALL_NER=true
ARG NER_MODEL=OskarBartoszyk/PLVeilBest
ENV HF_HOME=/models MASQE_NER_MODEL=${NER_MODEL}

COPY requirements.txt requirements-ner.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
# CPU-only PyTorch keeps the image small (no CUDA libraries).
RUN if [ "$INSTALL_NER" = "true" ]; then \
      pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch && \
      pip install --no-cache-dir -r requirements-ner.txt ; \
    fi
# Bake the model weights into the image so the container runs offline and the
# first request does not wait for a 500 MB download. A failed download is not
# fatal: the service then fetches the model on start-up or falls back to rules.
RUN if [ "$INSTALL_NER" = "true" ]; then \
      python3 -c "from huggingface_hub import snapshot_download; snapshot_download('${NER_MODEL}')" \
      || echo "WARNING: PII model not downloaded during build" ; \
    fi

COPY server.py model.py explain.py ghost.py ner_service.py /app/
COPY masqe_engine /app/masqe_engine
EXPOSE 8090
CMD ["python3", "/app/server.py"]
