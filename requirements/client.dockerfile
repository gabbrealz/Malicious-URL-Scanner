FROM python:3.13.1-alpine
WORKDIR /app
COPY requirements/client_requirements.txt .
RUN python -m pip install --upgrade pip && \
    python -m pip install -r client_requirements.txt && rm -f client_requirements.txt
COPY client client/
ENTRYPOINT [ "python", "client/client_main.py"]