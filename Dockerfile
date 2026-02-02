FROM python:3.14-slim-bookworm

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip setuptools
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m appuser && chown -R appuser /app
USER appuser

RUN openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"

ARG IP_SCRIPT
ARG IP_SCRIPT_PORT=8080

RUN sed -i \
    -e "s/const ip_script = \"[^\"]*\";/const ip_script = \"${IP_SCRIPT}\";/g" \
    -e "s/const ip_script_port = [0-9]*;/const ip_script_port = ${IP_SCRIPT_PORT};/g" \
    /app/inject*.js

RUN sed -i \
    -e '/ws.init/s!^//!!' /app/inject*.js

EXPOSE 8080
EXPOSE 1337

CMD ["python", "ws.py"]