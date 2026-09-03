FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

# NOTE: no USER instruction here — container runs as root by default.
# This is intentional for now; we'll fix it in a later pipeline step.
CMD ["python", "app.py"]
