FROM python:3.11.1-alpine3.17

COPY main.py /main.py
RUN pip install synologydsm-api==1.0.2 prometheus-client==0.15.0

EXPOSE 8080

ENTRYPOINT /main.py
