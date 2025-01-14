# OT Honey Pot using Docker

## Introduction
> This project is still under development, but if you like it you can star it :)

This Docker project is a honey pot that contain OT (Operational Technology) services.

Here is a list of the services: 

| Service | Working? |
| ----------- | ---------- |
| SSH  | ✅ |
| Telnet | ✅ | 
| MQTT | ✅ | 
| CoAp | ✅ | 
| Modbus | ✅ | 
| LogSystem | ✅  | 

## Instalation 
> You need to have docker installed on your server/machine. You can follow the [official Docker documentation](https://docs.docker.com/engine/install/) to do it.

Before download the repository, please check your umask setting by typing `umask`. The result should be `0022`.\
If it's not the case, you can change it temporarily for the current terminal session you're using by typing: `umask 0022`.\
It will ensure that the files are cloned with the right permission.\
After that you can download the repository using `git clone https://github.com/gabriel-lepinay/otpot.git`

## How to use it 

#### Attack map config
To get the API key for threat level calculation please register an account here abuseipdb.com then put the key in [/attack_map/key.txt](./attack_map/key.txt)

---

#### Data generator config
If you need more customization for the data generator you can change the **``config.json``**  file in the **[data_generator](./data_generator)** folder, the structure of the json should look like this.

```
{
  "web": {
    "port": 80
  },
  "mqtt": {
    "address": "mqqt.local",
    "port": 1883,
    "username": "user",
    "password": "password"
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

---

#### Mqtt config

For mqtt make sure to set an password in the [/mqtt/config/pwfile](./mqtt/config/)
the formate of the **pwfile** should be user:password, make sure you set this username and password in the data_generator config file as stated above.

---
#### Starting the Honeypot

You can run the HoneyPot just by starting the docker compose using: **`docker-compose up`** while being in the Otpot root directory.
You can check the containers's status using **`docker-compose ps`**

## API Documentation
(ip of docker):8080

### 1. `/points`
**Description:**  
Returns a list of individual IP geolocation data, including the country, latitude, longitude, request counts, and calculated threat levels for each IP.

**Method:**  
`GET`

**Response:**  
- **Content-Type:** `application/json`
- **Status Codes:** 
  - `200 OK`: Successfully retrieved data.

**Response Format:**
```json
[
  {
    "IP": "192.168.1.1",
    "Country": "United States",
    "Latitude": 37.751,
    "Longitude": -97.822,
    "RequestCount": 5,
    "ThreatLevel": 25
  },
  ...
]
```

**Example Request:**  
```bash
curl -X GET http://localhost:8080/points
```

---

### 2. `/countries`
**Description:**  
Returns aggregated geolocation data grouped by country, including the total count of IPs, total request counts, and the average threat level for each country.

**Method:**  
`GET`

**Response:**  
- **Content-Type:** `application/json`
- **Status Codes:** 
  - `200 OK`: Successfully retrieved data.

**Response Format:**
```json
{
  "United States": {
    "Country": "United States",
    "Latitude": 37.751,
    "Longitude": -97.822,
    "Count": 5,
    "RequestCount": 20,
    "AverageThreatLevel": 15.6
  },
  "Russia": {
    "Country": "Russia",
    "Latitude": 61.524,
    "Longitude": 105.318,
    "Count": 2,
    "RequestCount": 10,
    "AverageThreatLevel": 40.0
  },
  ...
}
```

**Example Request:**  
```bash
curl -X GET http://localhost:8080/countries
```

---

### 3. `/reload`
**Description:**  
Triggers a reload of log files to extract recent IPs and fetch their geolocation data. This endpoint updates the in-memory cache with the latest data.

**Method:**  
`POST`

**Response:**  
- **Content-Type:** `text/plain`
- **Status Codes:** 
  - `200 OK`: Successfully reloaded data.

**Response Body:**  
```plaintext
Data reload successful
```

**Example Request:**  
```bash
curl -X POST http://localhost:8080/reload
```

---

### 4. `/threats`
**Description:**  
Returns detailed threat-level information for a specific IP address.

**Method:**  
`GET`

**Query Parameters:**
- `ip` (required): The IP address to query.

**Response:**  
- **Content-Type:** `application/json`
- **Status Codes:** 
  - `200 OK`: Successfully retrieved threat level data for the IP.
  - `400 Bad Request`: Missing `ip` parameter.
  - `404 Not Found`: IP address not found in the records.

**Response Format (on success):**
```json
{
  "IP": "192.168.1.1",
  "Country": "United States",
  "Latitude": 37.751,
  "Longitude": -97.822,
  "RequestCount": 5,
  "ThreatLevel": 25
}
```

**Example Request:**  
```bash
curl -X GET "http://localhost:8080/threats?ip=192.168.1.1"
```

## Notes
- Log files are expected in the `/logs/` directory.
- To avoid rate-limiting issues, consider adding a delay when calling external APIs.
- Ensure the AbuseIPDB API key is stored in a `key.txt` file in the root directory.

