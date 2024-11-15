# OT Honey Pot using Docker

## Introduction

This Docker project is about making a honey pot that contain OT (Operational Technology) services.
As this project is under developpment everything is not setted up.

Here i a list of the services: 

| Service | Is working |
| ----------- | ---------- |
| SSH  | ✅ |
| Telnet | ✅ | 
| MQTT | ✅ | 
| CoAp | ✅ | 
| Modbus | ✅ | 
| LogSystem | ⏳ | 

## How to use it 

You can run the HoneyPot just by starting the docker compose using: `docker-compose up` while being in the otpot root directory.
You can check the containers status using `docker-compose ps`

## Notes

Do not forget to:

- Modyfing config file for the project final environment (eg. port forwarding, fake ip, last ssh connexion)
- Add how to use it documentation