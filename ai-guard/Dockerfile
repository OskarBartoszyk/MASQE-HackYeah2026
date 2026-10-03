FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY server.py /app/server.py
COPY model.py /app/model.py
COPY explain.py /app/explain.py
COPY ghost.py /app/ghost.py
EXPOSE 8090
CMD ["python3", "/app/server.py"]
