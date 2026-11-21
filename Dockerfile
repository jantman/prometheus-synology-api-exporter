FROM python:3.14.10-alpine3.24

COPY main.py /main.py
RUN pip install --no-cache-dir py-synologydsm-api==2.12.0 prometheus-client==0.26.0

EXPOSE 8080

ENTRYPOINT ["/main.py"]
