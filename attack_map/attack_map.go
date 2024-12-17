package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
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
	Country            string  `json:"country"`
	Latitude           float64 `json:"latitude"`
	Longitude          float64 `json:"longitude"`
	Count              int     `json:"count"`                // Count of IPs from this country
	RequestCount       int     `json:"request_count"`        // Total request count for the country
	AverageThreatLevel float64 `json:"average_threat_level"` // Average threat level for the country
}

// Global in-memory cache
var (
	ipData      = []APIResponse{}              // Slice for storing IP geolocation data
	countryData = make(map[string]CountryData) // Map for aggregated country data
	logIPs      = map[string]time.Time{}       // Map for IPs with timestamps
	ipCounts    = map[string]int{}             // Map to store request counts for each IP
)

// fetchGeoData loads the geolocation data for a specific IP from the external API
// fetchGeoData loads the geolocation data for a specific IP from the external API
func fetchGeoData(apiURL string, ip string) error {
	resp, err := http.Get(apiURL)
	if err != nil {
		return fmt.Errorf("error fetching geo data: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	// Parse the single response into an APIResponse struct
	var apiResponse APIResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return fmt.Errorf("error parsing JSON: %w", err)
	}

	// Set the IP for the response
	apiResponse.IP = ip

	// Calculate threat level
	failedAttempts := ipCounts[ip] // Use the request count as a proxy for failed login attempts
	threatLevel := calculateThreatLevel(ip, apiResponse.Country, failedAttempts)
	apiResponse.ThreatLevel = threatLevel

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

	return nil
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

// isExcluded checks if the IP is in the range 10.0.0.0/24
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

// getIPReputation simulates fetching IP reputation
// getIPReputation simulates fetching IP reputation
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
		"test_ips.txt", // Add the test IPs file
	}
	if err := parseLogs(logFiles); err != nil {
		log.Fatalf("Error parsing log files: %v", err)
	}

	// Filter IPs from the last month and fetch geolocation data
	recentIPs := filterIPs()
	for _, ip := range recentIPs {
		fmt.Printf("Fetching geo data for IP: %s\n", ip)
		apiURL := fmt.Sprintf("http://ip-api.com/json/%s", ip)
		if err := fetchGeoData(apiURL, ip); err != nil {
			log.Printf("Error fetching geo data for IP %s: %v", ip, err)
		}
		//time.Sleep(100 * time.Millisecond) // Sleep for 100ms to avoid rate limiting
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
	// Calculate average threat level for each country
	for country, data := range countryData {
		// Calculate total threat level for the country
		totalThreatLevel := 0
		for _, ip := range ipData {
			if ip.Country == country {
				// Include the ThreatLevel in the calculation
				totalThreatLevel += ip.ThreatLevel
			}
		}
		// Calculate the average threat level
		if data.Count > 0 {
			data.AverageThreatLevel = float64(totalThreatLevel) / float64(data.Count)
			data.AverageThreatLevel = math.Round(float64(totalThreatLevel)/float64(data.Count)*100) / 100
		}
		countryData[country] = data
	}

	// Return the aggregated country-level data with the average threat level
	json.NewEncoder(w).Encode(countryData)
}

func main() {
	// Serve API endpoints
	http.HandleFunc("/points", pointsHandler)
	http.HandleFunc("/countries", countriesHandler)
	http.HandleFunc("/reload", reloadHandler)
	http.HandleFunc("/threats", threatsHandler) // Add the threats endpoint

	// Serve static files
	http.Handle("/", http.FileServer(http.Dir("./static")))

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
