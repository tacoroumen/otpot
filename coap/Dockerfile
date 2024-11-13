FROM python:3.9-slim
RUN pip install aiocoap
COPY coap_server.py /coap_server.py
CMD ["python", "/coap_server.py"]
EXPOSE 5683/udp

