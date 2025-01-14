package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// APIResponse represents a single IP geolocation record
type APIResponse struct {
	IP           string  `json:"query"`
	Country      string  `json:"country"`
	Latitude     float64 `json:"lat"`
	Longitude    float64 `json:"lon"`
	RequestCount int     `json:"request_count"` // Request count for individual IP
	ThreatLevel  int     `json:"threat_level"`  // Threat level for the IP
}

// CountryData aggregates data for a country
type CountryData struct {
	Country        	string  `json:"country"`
	Latitude       	float64 `json:"latitude"`
	Longitude      	float64 `json:"longitude"`
	Count          	int     `json:"count"`            // Count of IPs from this country
	RequestCount   	int     `json:"request_count"`    // Total request count for the country
	MaxThreatLevel	int     `json:"max_threat_level"` // max threat level for the country
}

// Global in-memory cache
var (
	ipData      = []APIResponse{}              // Slice for storing IP geolocation data
	countryData = make(map[string]CountryData) // Map for aggregated country data
	logIPs      = map[string]time.Time{}       // Map for IPs with timestamps
	ipCounts    = map[string]int{}             // Map to store request counts for each IP
)

func loadConfig(configFile string) (*Config, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}
	return &config, nil
}

// fetchGeoData loads the geolocation data for a specific IP from the external API
func fetchGeoData(apiURL string, ip string) (string, error) { // Return the country name as a string

	resp, err := http.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("error fetching geo data: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	// Parse the single response into an APIResponse struct
	var apiResponse APIResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return "", fmt.Errorf("error parsing JSON: %w", err)
	}

	// Load configuration
	config, err := loadConfig("config.json")
	if err != nil {
		return "", fmt.Errorf("error loading config: %v", err)
	}

	// Set the IP for the response
	apiResponse.IP = ip

	threatLevelThreshold := config.ThreatLevelThreshold

	// Calculate threat level
	failedAttempts := ipCounts[ip] // Use the request count as a proxy for failed login attempts
	threatLevel := calculateThreatLevel(ip, apiResponse.Country, failedAttempts)
	apiResponse.ThreatLevel = threatLevel
	if threatLevel > threatLevelThreshold {
		subject := fmt.Sprintf("High Threat Alert: %d (%s, %s)", threatLevel, ip, apiResponse.Country)
		body := fmt.Sprintf("A threat with threat level %d has been detected. This exceeds the maximum allowed threat level of %d. Action is recommended. Threat is coming from IP: %s, with geolocation: %s. This threat has made %d requests ", threatLevel, config.ThreatLevelThreshold, ip, apiResponse.Country, apiResponse.RequestCount)
		err := sendEmail(subject, body)
		if err != nil {
			return "", fmt.Errorf("Error sending email: %v", err)
		}
	}

	// Append the single response to ipData
	ipData = append(ipData, apiResponse)

	// Aggregate country-level data
	country := countryData[apiResponse.Country]
	country.Country = apiResponse.Country
	country.Latitude = apiResponse.Latitude
	country.Longitude = apiResponse.Longitude
	country.Count++
	country.RequestCount += ipCounts[ip]
	countryData[apiResponse.Country] = country

	// Return the country as part of the response
	return apiResponse.Country, nil
}

// parseLogs reads .log files, extracts IP addresses, and stores them with timestamps
func parseLogs(logFiles []string) error {
	ipRegex := regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	for _, logFile := range logFiles {
		file, err := os.Open(logFile)
		if err != nil {
			return fmt.Errorf("error opening log file %s: %w", logFile, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			ipMatches := ipRegex.FindAllString(line, -1)
			for _, ip := range ipMatches {
				// Use the current date-time as a placeholder (if logs contain timestamps, use them instead)
				logIPs[ip] = time.Now()

				// Increment the request count for the IP
				ipCounts[ip]++
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading log file %s: %w", logFile, err)
		}
	}
	return nil
}

// isExcluded checks if the IP is in the range 10.10.0.0/24
func isExcluded(ip string) bool {
	_, cidr, _ := net.ParseCIDR("10.10.0.0/24")
	parsedIP := net.ParseIP(ip)
	return cidr.Contains(parsedIP)
}

// filterIPs filters IPs from the last month and excludes specific ranges
func filterIPs() []string {
	oneMonthAgo := time.Now().AddDate(0, -1, 0)
	var recentIPs []string
	for ip, timestamp := range logIPs {
		if timestamp.After(oneMonthAgo) && !isExcluded(ip) {
			recentIPs = append(recentIPs, ip)
		}
	}
	return recentIPs
}

// calculateThreatLevel calculates a threat level for the IP based on various factors
func calculateThreatLevel(ip string, country string, failedAttempts int) int {
	threatLevel := 0
	// Failed login attempts (Simulate with a fixed value, can be adjusted)
	threatLevel += int(float64(failedAttempts) * 0.25) // Increase threat level by 0.25 for each failed attempt

	// Reputation check (Placeholder - you would integrate an actual reputation service)
	reputation := getIPReputation(ip)
	threatLevel += reputation

	// Geolocation-based threat scoring (high-risk countries)
	if country == "Russia" || country == "China" {
		threatLevel += 25
	}

	if threatLevel > 100 { // Cap the threat level at 100
		threatLevel = 100
	}

	// Return the calculated threat level
	return threatLevel
}

func getIPReputation(ip string) int {
	// Your AbuseIPDB API key
	data, err := os.ReadFile("key.txt")
	if err != nil {
		fmt.Printf("error reading API key file: %s", err)
	}
	apiKey := strings.TrimSpace(string(data))
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating HTTP request: %v", err)
		return 0
	}

	// Set the required headers
	req.Header.Set("Key", apiKey)                // API key header
	req.Header.Set("Accept", "application/json") // Accept header for JSON response

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching IP reputation for %s: %v", ip, err)
		return 0
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to fetch data for IP %s: %s", ip, resp.Status)
		return 0
	}

	// Read and parse the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body for IP %s: %v", ip, err)
		return 0
	}

	// Parse the response as a JSON object
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		log.Printf("Error unmarshalling response for IP %s: %v", ip, err)
		return 0
	}

	// Extract the data object from the response
	if data, exists := response["data"].(map[string]interface{}); exists {
		// Extract the values we need, with type assertion checks
		isTor, _ := data["isTor"].(bool) // Safely assert type with a fallback if needed
		isWhitelisted, _ := data["isWhitelisted"].(bool)
		abuseConfidenceScore, _ := data["abuseConfidenceScore"].(float64) // Parse as float64

		// Calculate the threat level
		threatLevel := 0
		if isTor {
			threatLevel += 8
		}
		if isWhitelisted {
			threatLevel = 0
		}
		threatLevel += int(abuseConfidenceScore) // Convert float64 to int for threat level calculation

		return threatLevel
	}

	return 0 // Default to 0 if no data found
}

// threatsHandler serves the threat level for a specific IP
func threatsHandler(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "IP parameter is required", http.StatusBadRequest)
		return
	}

	// Check if the IP is in the logs and return the threat level
	for _, ipEntry := range ipData {
		if ipEntry.IP == ip {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ipEntry)
			return
		}
	}

	// If no IP found, return a 404
	http.Error(w, "IP not found", http.StatusNotFound)
}

func reloadHandler(w http.ResponseWriter, r *http.Request) {
	// Parse log files to extract IPs
	logFiles := []string{
		"/logs/coap.log",
		"/logs/mqtt.log",
		"/logs/modbus.log",
		"/logs/cowrie.log",
		//"test_ips.txt", // Add the test IPs file
	}
	if err := parseLogs(logFiles); err != nil {
		log.Fatalf("Error parsing log files: %v", err)
	}

// Filter IPs from the last month and fetch geolocation data
recentIPs := filterIPs()
for _, ip := range recentIPs {
	fmt.Printf("Fetching geo data for IP: %s\n", ip)
	apiURL := fmt.Sprintf("http://ip-api.com/json/%s", ip)

	// Fetch geo data and capture both error and country
	country, err := fetchGeoData(apiURL, ip)
	if err != nil {
		log.Printf("Error fetching geo data for IP %s: %v", ip, err)
	} else {
		// If geo data is fetched successfully, log the country
		fmt.Printf("Geo data for IP %s fetched successfully. Country: %s\n", ip, country)
	}
	// Optional: Add a sleep if you're rate-limiting
	// time.Sleep(100 * time.Millisecond)
}

	// After all IPs have been processed, send the response
	w.WriteHeader(http.StatusOK) // 200 OK status code
	w.Write([]byte("Data reload successful"))
}

// pointsHandler serves individual IP geolocation data
func pointsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Create a new slice for the response
	var response []APIResponse
	for _, ip := range ipData {
		// Set the request count for each IP
		ip.RequestCount = ipCounts[ip.IP]

		response = append(response, ip)
	}

	// Return the IP geolocation data with request counts and threat levels
	json.NewEncoder(w).Encode(response)
}

// countriesHandler serves aggregated country-level data
func countriesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Calculate the maximum threat level for each country
	for country, data := range countryData {
		// Initialize maxThreatLevel for the country
		maxThreatLevel := 0
		for _, ip := range ipData {
			if ip.Country == country {
				// Update maxThreatLevel if the current IP's ThreatLevel is higher
				if ip.ThreatLevel > maxThreatLevel {
					maxThreatLevel = ip.ThreatLevel
				}
			}
		}
		// Update the max threat level in the data
		data.MaxThreatLevel = maxThreatLevel
		countryData[country] = data
	}

	// Return the aggregated country-level data with the max threat level
	json.NewEncoder(w).Encode(countryData)
}

func sendEmail(subject, body string) error {
	// Load configuration
	config, err := loadConfig("config.json")
	if err != nil {
		return fmt.Errorf("error loading config: %v", err)
	}

	// Format for email
	msg := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body)

	// Email addresses and auth
	from := config.Username
	to := []string{config.Recipient}
	auth := smtp.PlainAuth("", config.Username, config.Password, config.SMTPServer)

	// Email sending
	err = smtp.SendMail(fmt.Sprintf("%s:%d", config.SMTPServer, config.SMTPPort), auth, from, to, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}
	return nil
}

func reloadDataAndSendEmail() error {
	// List of log files to parse
	logFiles := []string{
		"/logs/coap.log",
		"/logs/mqtt.log",
		"/logs/modbus.log",
		"/logs/cowrie.log",
	}

	// Parse the log files and extract IPs
	if err := parseLogs(logFiles); err != nil {
		return fmt.Errorf("error parsing log files: %v", err)
	}

	// Filter IPs from the last week
	recentIPs := filterIPsWeekly()
	fmt.Println(recentIPs)
	if len(recentIPs) == 0 {
		return fmt.Errorf("no recent IPs found to process")
	}

	var emailBody string
	for _, ip := range recentIPs {
		emailBody += fmt.Sprintf("Request made from the following IP: %s\n", ip)
	
		// Construct the API URL for geolocation
		apiURL := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	
		// Fetch the geo data for the IP and retrieve the country
		country, err := fetchGeoData(apiURL, ip)
		if err != nil {
			emailBody += fmt.Sprintf("Error fetching geo data for IP %s: %v\n", ip, err)
		} else {
			emailBody += fmt.Sprintf("Geo data for IP %s fetched successfully. Country of origin: %s\n", ip, country)
		}
	}
	
	// Send the email with the constructed email body
	subject := "Weekly Geo Data Report"
	err := sendEmail(subject, emailBody)
	if err != nil {
		log.Printf("Error sending email: %v", err)
	}

	// Return success
	return nil
}

// filterIPs filters IPs that are from the last week and excludes specific ranges
func filterIPsWeekly() []string {
	oneWeekAgo := time.Now().AddDate(0, 0, -7) // Date exactly 7 days ago
	var recentIPs []string

	// Iterate over all IPs and timestamps in logIPs
	for ip, timestamp := range logIPs {
		// Only include IPs that are from the last week and are not excluded
		if timestamp.After(oneWeekAgo) && !isExcluded(ip) {
			recentIPs = append(recentIPs, ip)
		}
	}
	return recentIPs
}

func scheduleWeeklyReload() {
	// Create a ticker that triggers every minute for demo purposes
	ticker := time.NewTicker(time.Second * 60)

	// Run the first reload immediately
	log.Printf("Tried sending an email")
	go reloadDataAndSendEmail()

	// Periodically call reloadDataAndSendEmail every 7 days
	for {
		select {
		case <-ticker.C:
			if err := reloadDataAndSendEmail(); err != nil {
				log.Printf("Error during scheduled data reload: %v", err)
			}
		}
	}
}

func main() {
	// Serve API endpoints
	http.HandleFunc("/points", pointsHandler)
	http.HandleFunc("/countries", countriesHandler)
	http.HandleFunc("/reload", reloadHandler)
	http.HandleFunc("/threats", threatsHandler) // Add the threats endpoint

	// Serve static files
	http.Handle("/", http.FileServer(http.Dir("./static")))

	go scheduleWeeklyReload()

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
