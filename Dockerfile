# Guard-only scaffold; configure storage before starting the service.
FROM python:3.13-slim
WORKDIR /app
COPY risk_guard/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY risk_guard/ /app/risk_guard/
ENV PYTHONUNBUFFERED=1 RISK_GUARD_HOST=0.0.0.0 RISK_GUARD_PORT=8091
EXPOSE 8091
CMD ["python", "-m", "risk_guard"]
