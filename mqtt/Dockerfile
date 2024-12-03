FROM eclipse-mosquitto:latest
COPY mosquitto.conf /mosquitto/config/mosquitto.conf
RUN chmod 0700 /mosquitto/config/pwfile
RUN chown root:root /mosquitto/config/pwfile
EXPOSE 1883
EXPOSE 9001

