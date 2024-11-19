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

=======
## Instalation 
You need to have docker installed on your server/machine. You can follow the [official Docker documentation](https://docs.docker.com/engine/install/) to do it.

Before download the repository, please check your umask setting by typing `umask`. The result should be `0022`.\
If it's not the case, you can change it temporarily for the current terminal session you're using by typing: `umask 0022`.\
It will ensure that the files are cloned with the right permission.\
After that you can download the repository using `git clone https://github.com/gabriel-lepinay/otpot.git`

## How to use it 

You need to create an **``config.json``** file in the **[data_generator](./data_generator)** folder the structure of the json should look like this.

```
{
  "web": {
    "port": 80
  },
  "mqtt": {
    "address": "localhost",
    "port": 1883
  },
  "coap": {
    "address": "localhost",
    "port": 5683
  },
  "modbus": {
    "address": "localhost",
    "port": 502
  }
}
```
Where the web sets the variables for the gui and the mqtt, coap and modbus set the connection values for the servers.

You can run the HoneyPot just by starting the docker compose using: **`docker-compose up`** while being in the otpot root directory.
You can check the containers status using **`docker-compose ps`**

## Notes

Do not forget to:

- Modyfing config file for the project final environment (eg. port forwarding, fake ip, last ssh connexion)
- Add how to use it documentation