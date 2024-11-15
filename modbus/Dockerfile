FROM python:3.9-slim
RUN pip install pymodbus==3.7.4
COPY modbus_server.py /modbus_server.py
COPY helper.py /helper.py
CMD ["python", "/modbus_server.py"]
EXPOSE 502
