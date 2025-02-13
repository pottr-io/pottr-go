package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	// Rotate threshold in bytes for the active /var/log/auth.log
	rotateThreshold = 1024 // e.g. rotate if file size >= 1 KB
)

// lastReadOffsets keeps track of how many bytes of each file have been read already.
// We'll focus particularly on /var/log/auth.log. Rotated/compressed logs typically get
// read once in full (since they no longer grow).
var lastReadOffsets = struct {
	sync.Mutex
	offsets map[string]int64
}{
	offsets: make(map[string]int64),
}

// computeFileHash returns the SHA256 hex digest of a file's *raw* data.
// For .gz files, we hash the compressed bytes (not the uncompressed).
func computeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// rotateFile renames (rotates) the active log file if it exceeds the threshold.
func rotateFile(filePath string) {
	fi, err := os.Stat(filePath)
	if err != nil {
		log.Printf("Error stating file %s: %v", filePath, err)
		return
	}

	if fi.Size() < rotateThreshold {
		// Not big enough to rotate.
		return
	}

	newName := filePath + "." + time.Now().Format("20060102_150405")
	err = os.Rename(filePath, newName)
	if err != nil {
		log.Printf("Error rotating file %s: %v", filePath, err)
		return
	}
	log.Printf("Rotated file %s -> %s", filePath, newName)

	// Clear any stored offset for the old file path.
	lastReadOffsets.Lock()
	delete(lastReadOffsets.offsets, filePath)
	lastReadOffsets.Unlock()
}

// scanAuthLog scans lines (plain or gz) for login events and writes them to the DB.
// For the active log, we only read lines that appear *after* our last-known offset
// to avoid duplicates. For rotated logs, we read the whole file (but skip if the
// file hash is unchanged).
func scanAuthLog(
	filePath string,
	fileHash string,
	db *sql.DB,
	ipPattern, validUserPattern, invalidUserPattern *regexp.Regexp,
	sendToAPI bool,
) {
	// We open the file (whether gzipped or plain):
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening %s: %v", filePath, err)
		return
	}
	defer file.Close()

	var (
		scanner     *bufio.Scanner
		startOffset int64
	)

	isGzip := strings.HasSuffix(filePath, ".gz")

	if isGzip {
		log.Printf("[scanAuthLog] %s is gzipped, reading from start (cannot partial-seek in gz).", filePath)
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			log.Printf("Error creating gzip reader for %s: %v", filePath, err)
			return
		}
		defer gzReader.Close()
		scanner = bufio.NewScanner(gzReader)
	} else {
		// For plain text files, we can seek to the last offset if we have one.
		lastReadOffsets.Lock()
		startOffset = lastReadOffsets.offsets[filePath]
		lastReadOffsets.Unlock()

		_, err := file.Seek(startOffset, io.SeekStart)
		if err != nil {
			log.Printf("[scanAuthLog] Error seeking %s to offset %d: %v", filePath, startOffset, err)
			// We'll fall back to reading from the start if Seek fails.
			file.Seek(0, io.SeekStart)
		}
		log.Printf("[scanAuthLog] %s reading from offset %d", filePath, startOffset)

		scanner = bufio.NewScanner(file)
	}

	linesScanned := 0
	recordsFound := 0
	currentOffset := startOffset

	for scanner.Scan() {
		line := scanner.Text()
		linesScanned++
		// Compute offset for this line in a naive way by adding length of text + 1 (newline).
		// (For gz we won't track offsets; it's always from start if re-hashed.)
		if !isGzip {
			currentOffset += int64(len(line)) + 1
		}

		// If you have extremely verbose logs, you may want to reduce this:
		log.Printf("[%s] Line: %s", filePath, line)

		// Match the IP from the line:
		ipMatch := ipPattern.FindStringSubmatch(line)
		if ipMatch == nil {
			continue
		}
		ip := ipMatch[1]

		// Determine if we found a "valid user" or "invalid user"
		// Note that you may also want to handle "Failed password for" lines, etc.
		var username string
		if validMatch := validUserPattern.FindStringSubmatch(line); validMatch != nil {
			username = validMatch[1]
		} else if invalidMatch := invalidUserPattern.FindStringSubmatch(line); invalidMatch != nil {
			username = invalidMatch[1]
		} else {
			// IP found but no recognized username pattern.
			continue
		}

		// For the "time" field, you might parse the real date from the log line, but
		// for now we just store the current time:
		currentTime := time.Now().Format(time.RFC3339)

		// Upsert logic:
		insertQuery := `
			INSERT INTO realtime (ip, username, time, attempts, source_file, file_hash)
			VALUES ($1, $2, $3, 1, $4, $5)
			ON CONFLICT (ip, username)
			DO UPDATE SET
				time = EXCLUDED.time,
				attempts = realtime.attempts + 1,
				source_file = EXCLUDED.source_file,
				file_hash = EXCLUDED.file_hash
		`
		_, err = db.Exec(insertQuery, ip, username, currentTime, filePath, fileHash)
		if err != nil {
			log.Printf("DB upsert error for IP=%s user=%s: %v", ip, username, err)
			continue
		}
		recordsFound++

		// Optionally send to API:
		if sendToAPI {
			form := url.Values{}
			form.Add("ip", ip)
			form.Add("username", username)
			form.Add("time", currentTime)
			form.Add("source_file", filePath)
			form.Add("file_hash", fileHash)

			resp, err := http.PostForm("https://core.pottr.io/readauth.php", form)
			if err != nil {
				log.Printf("Error sending data to core API for IP=%s user=%s: %v", ip, username, err)
			} else {
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Printf("Error reading API response for IP=%s user=%s: %v", ip, username, err)
				} else {
					log.Printf("API response for IP=%s user=%s: %s", ip, username, string(body))
				}
				resp.Body.Close()
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[scanAuthLog] Error scanning file %s: %v", filePath, err)
	}

	log.Printf("[scanAuthLog] Completed reading %s. Lines scanned: %d, records found: %d.", filePath, linesScanned, recordsFound)

	// Update our last offset for next time (only for the active log or any plain-text log).
	// For gz files, we rely on the file hash to skip unchanged data.
	if !isGzip {
		lastReadOffsets.Lock()
		lastReadOffsets.offsets[filePath] = currentOffset
		lastReadOffsets.Unlock()
	}
}

func main() {
	// CLI flag to optionally send data to the remote API
	sendToAPI := flag.Bool("send-to-api", false, "Send details to the core API endpoint")
	flag.Parse()

	// Set up log rotation for our own logging
	log.SetOutput(&lumberjack.Logger{
		Filename:   "/var/log/pottr/readauth.log",
		MaxSize:    1,  // in megabytes
		MaxBackups: 20, // keep up to 20 old logs
		Compress:   false,
	})
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting auth log scanner...")

	// Connect to Postgres
	connStr := "postgres://postgres:Bernie3121!@localhost:5432/postgres?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("DB connection error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("DB ping error: %v", err)
	}
	log.Println("Connected to PostgreSQL successfully.")

	// Create (or ensure) table with primary key on (ip, username)
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS realtime (
		ip TEXT,
		username TEXT,
		time TEXT,
		attempts INT DEFAULT 1,
		source_file TEXT,
		file_hash TEXT,
		PRIMARY KEY (ip, username)
	)`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		log.Fatalf("Error creating table 'realtime': %v", err)
	}
	log.Println("Table 'realtime' ready.")

	// Compile regex
	ipPattern := regexp.MustCompile(`([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`)
	validUserPattern := regexp.MustCompile(`Accepted password for (\S+) from ([^\s]+)`)
	invalidUserPattern := regexp.MustCompile(`Invalid user (\S+) from ([^\s]+)`)

	// Maintain a cache: filename -> last known hash
	fileHashes := make(map[string]string)

	for {
		log.Println("Looking for /var/log/auth.log* files...")
		logFiles, err := filepath.Glob("/var/log/auth.log*")
		if err != nil {
			log.Printf("Error in Glob: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(logFiles) == 0 {
			log.Println("No auth.log files found.")
		} else {
			log.Printf("Found %d log files.", len(logFiles))
		}

		for _, logFilePath := range logFiles {
			// Compute file hash (raw bytes)
			fileHash, err := computeFileHash(logFilePath)
			if err != nil {
				log.Printf("Error hashing %s: %v", logFilePath, err)
				continue
			}

			oldHash, alreadySeen := fileHashes[logFilePath]
			if alreadySeen {
				if oldHash == fileHash {
					// No change, skip (especially relevant for rotated/compressed logs)
					if logFilePath != "/var/log/auth.log" {
						log.Printf("File %s unchanged. Skipping.", logFilePath)
						continue
					}
					// For the *active* log, we still might have new lines appended, so we do NOT skip
					// purely by identical hash. We rely on offset logic to see if there's new data appended.
					log.Printf("Active log %s has same hash, but we will still seek new lines by offset.", logFilePath)
				} else {
					log.Printf("File %s changed (hash %s -> %s).", logFilePath, oldHash, fileHash)
				}
			} else {
				log.Printf("First time seeing %s, hash = %s", logFilePath, fileHash)
			}
			fileHashes[logFilePath] = fileHash

			// Scan file for new records
			scanAuthLog(logFilePath, fileHash, db, ipPattern, validUserPattern, invalidUserPattern, *sendToAPI)

			// If this is the active log, consider rotating it
			if logFilePath == "/var/log/auth.log" {
				rotateFile(logFilePath)
			}
		}

		log.Println("Sleeping 5s before next pass...")
		time.Sleep(5 * time.Second)
	}
}
