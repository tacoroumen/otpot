FROM eclipse-mosquitto:latest
COPY config/mosquitto.conf /mosquitto/config/mosquitto.conf
COPY config/pwfile /mosquitto/config/pwfile
USER root
RUN chmod 0700 /mosquitto/config/pwfile
RUN chown root:root /mosquitto/config/pwfile
EXPOSE 1883
EXPOSE 9001

