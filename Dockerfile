FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 opspilot && mkdir /data && chown opspilot /data
COPY . .
USER opspilot
ENV OPSPILOT_DATABASE_URL=sqlite:////data/opspilot.db
CMD ["sh", "-c", "python -m app.storage.bootstrap && exec uvicorn app.api.main:app --host 0.0.0.0 --port 8000"]
