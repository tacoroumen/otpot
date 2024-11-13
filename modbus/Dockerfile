FROM python:3.9-slim
RUN pip install pymodbus
COPY modbus_server.py /modbus_server.py
CMD ["python", "/modbus_server.py"]
EXPOSE 502

