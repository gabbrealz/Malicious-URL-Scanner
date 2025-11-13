FROM python:3.13.1-alpine
WORKDIR /app
COPY requirements/server_requirements.txt .
RUN python -m pip install --upgrade pip && \
    python -m pip install -r server_requirements.txt && rm -f server_requirements.txt
COPY server server/
EXPOSE 8080 
ENTRYPOINT [ "python", "server/server_main.py"]