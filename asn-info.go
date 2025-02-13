package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ipinfo/go/v2/ipinfo"
	"github.com/ipinfo/go/v2/ipinfo/cache"
	_ "github.com/lib/pq"
)

// IPInfoResponse matches the structure of IP data from ipinfo.
// Adjust/add fields if your ipinfo response differs or expands.
type IPInfoResponse struct {
	IP       string `json:"ip"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	City     string `json:"city"`
	Postal   string `json:"postal"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Timezone string `json:"timezone"`

	Continent struct {
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"continent"`

	CountryFlag struct {
		Emoji   string `json:"emoji"`
		Unicode string `json:"unicode"`
	} `json:"country_flag"`

	CountryName string `json:"country_name"`

	CountryCurrency struct {
		Code   string `json:"code"`
		Symbol string `json:"symbol"`
	} `json:"country_currency"`

	CountryFlagURL string `json:"country_flag_url"`
}

func main() {
	//-------------------------------------
	// 1. Connect to Postgres
	//-------------------------------------
	// Update the connection string with your own credentials and DB info.
	connStr := "host=localhost port=5432 user=postgres password=postgres dbname=postgres sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	// Verify the connection is up.
	if err = db.Ping(); err != nil {
		log.Fatalf("Cannot connect to database: %v", err)
	}

	//-------------------------------------
	// 2. Ensure 'asninfo' table exists
	//-------------------------------------
	// This schema has columns matching fields in IPInfoResponse.
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS asninfo (
		ip                     TEXT PRIMARY KEY,
		loc                    TEXT,
		org                    TEXT,
		city                   TEXT,
		postal                 TEXT,
		region                 TEXT,
		country                TEXT,
		timezone               TEXT,
		continent_code         TEXT,
		continent_name         TEXT,
		country_flag_emoji     TEXT,
		country_flag_unicode   TEXT,
		country_name           TEXT,
		country_currency_code  TEXT,
		country_currency_symbol TEXT,
		country_flag_url       TEXT
	)`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		log.Fatalf("Failed to create 'asninfo' table: %v", err)
	}

	//-------------------------------------
	// 3. Fetch IPs from the 'realtime' table
	//-------------------------------------
	rows, err := db.Query("SELECT ip FROM realtime")
	if err != nil {
		log.Fatalf("Failed to query 'realtime' table: %v", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			log.Fatalf("Error scanning IP: %v", err)
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("Error reading rows: %v", err)
	}

	// If no IPs found, exit early
	if len(ips) == 0 {
		log.Println("No IPs found in the realtime table.")
		return
	}

	//-------------------------------------
	// 4. Initialize the IPInfo client
	//-------------------------------------
	// Replace "YOUR_TOKEN" with your actual IPInfo token.
	client := ipinfo.NewClient(
		nil,
		ipinfo.NewCache(cache.NewInMemory().WithExpiration(5*time.Minute)),
		"276c403ca20350",
	)

	//-------------------------------------
	// 5. Determine batch size & chunk the IPs
	//-------------------------------------
	maxBatchSize := 50 // adjust as needed
	ipChunks := chunkIPs(ips, maxBatchSize)

	//-------------------------------------
	// 6. For each chunk, do a batch lookup and insert results into 'asninfo'
	//-------------------------------------
	for _, chunk := range ipChunks {
		batchResult, err := client.GetBatch(
			chunk,
			ipinfo.BatchReqOpts{
				BatchSize:       2,
				TimeoutPerBatch: 0,
				TimeoutTotal:    5,
			},
		)
		if err != nil {
			log.Printf("Batch lookup failed for chunk: %v\nError: %v\n", chunk, err)
			continue
		}

		ctx := context.Background()

		// For each IP -> info, parse the JSON and insert into columns
		for ip, info := range batchResult {
			// Convert `info` to JSON
			jsonData, err := json.Marshal(info)
			if err != nil {
				log.Printf("Error marshaling info for IP %s: %v\n", ip, err)
				continue
			}

			// Parse into IPInfoResponse struct
			var parsed IPInfoResponse
			if err := json.Unmarshal(jsonData, &parsed); err != nil {
				log.Printf("Error unmarshaling JSON for IP %s: %v\n", ip, err)
				continue
			}

			// Upsert each parsed field into asninfo
			_, err = db.ExecContext(
				ctx,
				`INSERT INTO asninfo (
					ip, 
					loc, 
					org, 
					city, 
					postal, 
					region, 
					country, 
					timezone, 
					continent_code, 
					continent_name, 
					country_flag_emoji,
					country_flag_unicode,
					country_name,
					country_currency_code,
					country_currency_symbol,
					country_flag_url
				)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
				ON CONFLICT (ip) DO UPDATE
					SET
						loc = EXCLUDED.loc,
						org = EXCLUDED.org,
						city = EXCLUDED.city,
						postal = EXCLUDED.postal,
						region = EXCLUDED.region,
						country = EXCLUDED.country,
						timezone = EXCLUDED.timezone,
						continent_code = EXCLUDED.continent_code,
						continent_name = EXCLUDED.continent_name,
						country_flag_emoji = EXCLUDED.country_flag_emoji,
						country_flag_unicode = EXCLUDED.country_flag_unicode,
						country_name = EXCLUDED.country_name,
						country_currency_code = EXCLUDED.country_currency_code,
						country_currency_symbol = EXCLUDED.country_currency_symbol,
						country_flag_url = EXCLUDED.country_flag_url
				`,
				parsed.IP,
				parsed.Loc,
				parsed.Org,
				parsed.City,
				parsed.Postal,
				parsed.Region,
				parsed.Country,
				parsed.Timezone,
				parsed.Continent.Code,
				parsed.Continent.Name,
				parsed.CountryFlag.Emoji,
				parsed.CountryFlag.Unicode,
				parsed.CountryName,
				parsed.CountryCurrency.Code,
				parsed.CountryCurrency.Symbol,
				parsed.CountryFlagURL,
			)
			if err != nil {
				log.Printf("Error inserting IP %s into asninfo: %v\n", ip, err)
			} else {
				log.Printf("Inserted/Updated IP %s into asninfo.\n", ip)
			}
		}
	}

	fmt.Println("Done processing IP batches.")
}

// chunkIPs divides the input slice of IPs into smaller slices of size chunkSize.
func chunkIPs(ips []string, chunkSize int) [][]string {
	var chunks [][]string
	for i := 0; i < len(ips); i += chunkSize {
		end := i + chunkSize
		if end > len(ips) {
			end = len(ips)
		}
		chunks = append(chunks, ips[i:end])
	}
	return chunks
}
