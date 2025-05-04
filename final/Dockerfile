# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy meta files
COPY config.py .
COPY run.py .
COPY setup.sql .

# Copy the source code
COPY src src

# for external API access
EXPOSE 8000

# for internal communication
EXPOSE 8001

CMD [ "python", "run.py" ]