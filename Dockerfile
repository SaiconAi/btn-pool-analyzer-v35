FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app

ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8765
ENV DATA_DIR=/app/data

RUN mkdir -p /app/data/reports
EXPOSE 8765
CMD ["python", "server.py"]
