FROM python:3.11-slim

WORKDIR /app
COPY rules.py srv.py ./

EXPOSE 8000
CMD ["python", "srv.py"]
