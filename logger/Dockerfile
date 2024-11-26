FROM docker.elastic.co/beats/filebeat:7.10.0
COPY filebeat.yml /usr/share/filebeat/filebeat.yml

# Set permissions
RUN chmod 644 /usr/share/filebeat/filebeat.yml
RUN chmod -R 777 /logs