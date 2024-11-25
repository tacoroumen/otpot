# OT Honey Pot using Docker

## Introduction
> This project is still under development, but if you like it you can start it :)

This Docker project is a honey pot that contain OT (Operational Technology) services.

Here is a list of the services: 

| Service | Working? |
| ----------- | ---------- |
| SSH  | ✅ |
| Telnet | ✅ | 
| MQTT | ✅ | 
| CoAp | ✅ | 
| Modbus | ✅ | 
| LogSystem | ⏳ | 

## Instalation 
> You need to have docker installed on your server/machine. You can follow the [official Docker documentation](https://docs.docker.com/engine/install/) to do it.

Before download the repository, please check your umask setting by typing `umask`. The result should be `0022`.\
If it's not the case, you can change it temporarily for the current terminal session you're using by typing: `umask 0022`.\
It will ensure that the files are cloned with the right permission.\
After that you can download the repository using `git clone https://github.com/gabriel-lepinay/otpot.git`

## How to use it 
If you need more customization for the data generator you can change the **``config.json``**  file in the **[data_generator](./data_generator)** folder, the structure of the json should look like this.

```
{
  "web": {
    "port": 80
  },
  "mqtt": {
    "address": "mqqt.local",
    "port": 1883
  },
  "coap": {
    "address": "coap.local",
    "port": 5683
  },
  "modbus": {
    "address": "modbus.local",
    "port": 502
  }
}
```
Where the web sets the variables for the gui and the mqtt, coap and modbus set the connection values for the servers.

You can run the HoneyPot just by starting the docker compose using: **`docker-compose up`** while being in the Otpot root directory.
You can check the containers's status using **`docker-compose ps`**