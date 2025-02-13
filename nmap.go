package main

import (
	"context"
	"database/sql"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

// ----------------------------------------------------
// Nmap XML Structs
// ----------------------------------------------------

// NmapRun is the root element in Nmap XML output.
type NmapRun struct {
	Hosts []Host `xml:"host"`
}

// Host in the Nmap XML.
type Host struct {
	Status    Status    `xml:"status"`
	Addresses []Address `xml:"address"`
	Ports     Ports     `xml:"ports"`
	OS        *OS       `xml:"os"` // Pointer so we can detect absence.
}

// Status indicates if the host is up/down.
type Status struct {
	State string `xml:"state,attr"`
}

// Address can be ipv4, ipv6, mac, etc.
type Address struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

// Ports is a collection of PortElement.
type Ports struct {
	PortElements []PortElement `xml:"port"`
}

// PortElement holds details about a specific port.
type PortElement struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   int     `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}

// State for a single port.
type State struct {
	State string `xml:"state,attr"`
}

// Service holds extra info about a service on a port.
type Service struct {
	Name    string `xml:"name,attr,omitempty"`
	Product string `xml:"product,attr,omitempty"`
	Version string `xml:"version,attr,omitempty"`
}

// OS contains a list of OSMatches.
type OS struct {
	OSMatches []OSMatch `xml:"osmatch"`
}

// OSMatch is a guessed OS name and accuracy.
type OSMatch struct {
	Name     string    `xml:"name,attr"`
	Accuracy int       `xml:"accuracy,attr"`
	OSClass  []OSClass `xml:"osclass"`
}

// OSClass adds detail about vendor, family, etc.
type OSClass struct {
	Vendor   string `xml:"vendor,attr,omitempty"`
	OSFamily string `xml:"osfamily,attr,omitempty"`
}

// ----------------------------------------------------
// Global Configuration
// ----------------------------------------------------

var (
	db             *sql.DB
	maxConcurrency = 5 // Number of parallel scans
	nmapTimeout    = 2 * time.Minute
)

// ----------------------------------------------------
// main
// ----------------------------------------------------

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Optional CLI flag to do additional actions after scanning (stubbed).
	sendToAPI := flag.Bool("send-to-api", false, "Send results to external API (placeholder)")
	flag.Parse()

	// Connect to Postgres
	connStr := "postgres://postgres:Bernie3121!@localhost:5432/postgres?sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("DB open error: %v", err)
	}
	defer db.Close()

	// Basic check
	if err := db.Ping(); err != nil {
		log.Fatalf("DB ping error: %v", err)
	}

	// Ensure relevant tables, function, and trigger
	if err := ensureSchemaAndTrigger(); err != nil {
		log.Fatalf("Schema/trigger creation error: %v", err)
	}

	// Start the listener for realtime inserts
	if err := startListener(connStr, *sendToAPI); err != nil {
		log.Fatalf("Listener error: %v", err)
	}

	// The listener runs indefinitely. We'll block here.
	select {}
}

// ----------------------------------------------------
// Database Setup: Tables + Trigger
// ----------------------------------------------------

// ensureSchemaAndTrigger creates the necessary tables, function, and trigger if they don’t exist.
func ensureSchemaAndTrigger() error {
	// 1. Create 'realtime' table (just in case).
	realtimeTable := `
	CREATE TABLE IF NOT EXISTS realtime (
		ip TEXT PRIMARY KEY,
		username TEXT,
		time TEXT,
		attempts INT DEFAULT 1
	);
	`
	if _, err := db.Exec(realtimeTable); err != nil {
		return fmt.Errorf("creating realtime table: %v", err)
	}

	// 2. Create 'nmap_scan' table
	nmapScan := `
	CREATE TABLE IF NOT EXISTS nmap_scan (
		ip TEXT PRIMARY KEY,
		os_guess TEXT,
		os_accuracy INT,
		scanned_at TIMESTAMP
	);
	`
	if _, err := db.Exec(nmapScan); err != nil {
		return fmt.Errorf("creating nmap_scan table: %v", err)
	}

	// 3. Create 'nmap_ports' table
	nmapPorts := `
	CREATE TABLE IF NOT EXISTS nmap_ports (
		id SERIAL PRIMARY KEY,
		ip TEXT NOT NULL,
		port INT,
		protocol TEXT,
		state TEXT,
		service_name TEXT,
		service_product TEXT,
		service_version TEXT,
		scanned_at TIMESTAMP
	);
	`
	if _, err := db.Exec(nmapPorts); err != nil {
		return fmt.Errorf("creating nmap_ports table: %v", err)
	}

	// 4. Create or replace the PL/pgSQL function to do NOTIFY
	notifyFunc := `
	CREATE OR REPLACE FUNCTION notify_realtime_insert()
	RETURNS TRIGGER AS $$
	BEGIN
		IF TG_OP = 'INSERT' THEN
			PERFORM pg_notify('realtime_insert', NEW.ip);
		END IF;
		RETURN NEW;
	END;
	$$ LANGUAGE plpgsql;
	`
	if _, err := db.Exec(notifyFunc); err != nil {
		return fmt.Errorf("creating notify function: %v", err)
	}

	// 5. Create the trigger to call that function after inserts
	dropTrigger := `DROP TRIGGER IF EXISTS realtime_insert_trigger ON realtime;`
	if _, err := db.Exec(dropTrigger); err != nil {
		return fmt.Errorf("dropping old trigger: %v", err)
	}

	createTrigger := `
	CREATE TRIGGER realtime_insert_trigger
	AFTER INSERT ON realtime
	FOR EACH ROW
	EXECUTE FUNCTION notify_realtime_insert();
	`
	if _, err := db.Exec(createTrigger); err != nil {
		return fmt.Errorf("creating trigger: %v", err)
	}

	log.Println("Tables, function, and trigger ensured successfully.")
	return nil
}

// ----------------------------------------------------
// Listen for Notifications with pq.Listener
// ----------------------------------------------------

// startListener opens a pq.Listener on the "realtime_insert" channel,
// then spawns a worker pool to process IPs as soon as they arrive.
func startListener(connStr string, sendToAPI bool) error {
	listener := pq.NewListener(connStr, 10*time.Second, time.Minute, eventCallback)
	if err := listener.Listen("realtime_insert"); err != nil {
		return fmt.Errorf("cannot listen on channel realtime_insert: %v", err)
	}
	log.Println("Listening on channel 'realtime_insert'...")

	// Create a worker pool
	ipChan := make(chan string, 100)
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				processIP(ip, sendToAPI)
			}
		}()
	}

	// We'll keep reading notifications forever
	go func() {
		for {
			select {
			case n := <-listener.Notify:
				if n == nil {
					// Possibly a disconnect?
					log.Println("Listener returned nil notification.")
					time.Sleep(5 * time.Second)
					continue
				}
				ip := n.Extra // The payload is the IP
				log.Printf("Got NOTIFY: new IP inserted: %s", ip)
				ipChan <- ip

			case <-time.After(90 * time.Second):
				// Periodic check of the listener
				log.Println("No new notifications for 90s, checking connection...")
				go func() {
					if err := listener.Ping(); err != nil {
						log.Printf("Listener ping error: %v", err)
					}
				}()
			}
		}
	}()

	return nil
}

// eventCallback is a callback that pq.Listener calls on certain state changes (like reconnect attempts).
func eventCallback(ev pq.ListenerEventType, err error) {
	if err != nil {
		log.Printf("Listener event: %v, err=%v", ev, err)
	}
}

// ----------------------------------------------------
// Nmap Logic
// ----------------------------------------------------

// processIP checks if IP is already in nmap_scan; if not, runs a deep Nmap scan, parses, and stores results.
func processIP(ip string, sendToAPI bool) {
	// 1. Check if IP already scanned
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM nmap_scan WHERE ip = $1)`, ip).Scan(&exists); err != nil {
		log.Printf("Error checking nmap_scan for IP %s: %v", ip, err)
		return
	}
	if exists {
		log.Printf("Skipping IP %s (already in nmap_scan).", ip)
		return
	}

	// 2. Run nmap
	log.Printf("Starting Nmap scan for IP: %s", ip)
	xmlOutput, err := runDeepNmap(ip)
	if err != nil {
		log.Printf("Nmap error for %s: %v", ip, err)
		return
	}

	// 3. Parse & store
	if err := parseAndStoreNmapResults(ip, xmlOutput); err != nil {
		log.Printf("parseAndStore error for %s: %v", ip, err)
		return
	}

	// 4. Optionally do more
	if sendToAPI {
		log.Printf("(Stub) Would send IP %s results to external API here.", ip)
	}
}

// runDeepNmap executes Nmap with OS detection and returns XML results.
func runDeepNmap(ip string) (string, error) {
	args := []string{
		"-sS",      // TCP SYN
		"-sV",      // Service/version detection
		"-O",       // OS detection
		"-A",       // Aggressive
		"-T4",      // Faster
		"-Pn",      // Don't ping
		"-oX", "-", // Output as XML to stdout
		ip,
	}
	ctx, cancel := context.WithTimeout(context.Background(), nmapTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return "", fmt.Errorf("nmap scan timed out for %s", ip)
	}
	if err != nil {
		return "", fmt.Errorf("%v (output: %s)", err, string(out))
	}
	return string(out), nil
}

// parseAndStoreNmapResults parses the XML, stores OS info into nmap_scan, and open ports into nmap_ports.
func parseAndStoreNmapResults(scanIP, xmlOutput string) error {
	var nmapRun NmapRun
	if err := xml.Unmarshal([]byte(xmlOutput), &nmapRun); err != nil {
		return fmt.Errorf("XML unmarshal: %v", err)
	}
	if len(nmapRun.Hosts) == 0 {
		log.Printf("No hosts found in Nmap output for IP %s.", scanIP)
		return nil
	}

	now := time.Now()

	// Typically there's one host for a single IP. But let's loop in case Nmap reports more.
	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			continue
		}

		// Attempt to find a real IPv4 address in the host data
		primaryIP := scanIP
		for _, addr := range host.Addresses {
			if addr.Type == "ipv4" {
				primaryIP = addr.Addr
				break
			}
		}
		// Insert host-level data (OS guess, etc.)
		osGuess, osAccuracy := extractOSInfo(host)

		_, err := db.Exec(`
			INSERT INTO nmap_scan (ip, os_guess, os_accuracy, scanned_at)
			VALUES ($1, $2, $3, $4)
		`, primaryIP, osGuess, osAccuracy, now)
		if err != nil {
			log.Printf("insert nmap_scan error for IP=%s: %v", primaryIP, err)
			continue
		}
		log.Printf("Inserted nmap_scan row for IP=%s (OS=%s, accuracy=%d).", primaryIP, osGuess, osAccuracy)

		// Insert open ports
		for _, p := range host.Ports.PortElements {
			if p.State.State != "open" {
				continue
			}
			_, err = db.Exec(`
				INSERT INTO nmap_ports (
					ip, port, protocol, state,
					service_name, service_product, service_version,
					scanned_at
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			`,
				primaryIP,
				p.PortID,
				p.Protocol,
				p.State.State,
				p.Service.Name,
				p.Service.Product,
				p.Service.Version,
				now,
			)
			if err != nil {
				log.Printf("insert nmap_ports error for IP=%s port=%d: %v", primaryIP, p.PortID, err)
			} else {
				log.Printf("Inserted open port %d/%s for IP=%s.", p.PortID, p.Protocol, primaryIP)
			}
		}
	}

	return nil
}

// extractOSInfo picks the first OS match from the host
func extractOSInfo(h Host) (string, int) {
	if h.OS == nil || len(h.OS.OSMatches) == 0 {
		return "", 0
	}
	best := h.OS.OSMatches[0]
	return best.Name, best.Accuracy
}
