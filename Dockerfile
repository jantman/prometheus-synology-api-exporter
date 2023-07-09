FROM python:3.11.4-alpine3.18

COPY main.py /main.py
RUN pip install synologydsm-api==1.0.2 prometheus-client==0.17.0

EXPOSE 8080

ENTRYPOINT /main.py
