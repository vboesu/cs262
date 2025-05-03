# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# 1) install deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2) copy your app
COPY app .

# for external API access
EXPOSE 8000

# for internal communication
EXPOSE 8001

CMD [ "python", "run.py" ]