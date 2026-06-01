FROM python:3.12-slim

WORKDIR /app

# System deps (needed for psycopg2-binary native wheel)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default: run the web API + dashboard on 0.0.0.0:5000
EXPOSE 5000
CMD ["python", "api.py", "--host", "0.0.0.0", "--port", "5000"]
