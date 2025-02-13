package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	_ "github.com/lib/pq" // PostgreSQL driver
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// Crawler encapsulates the crawling logic and state.
type Crawler struct {
	db           *sql.DB
	storeImages  bool
	skipHTML     bool
	skipImages   bool
	baseDomains  map[string]bool // Tracks allowed base domains
	visitedLinks map[string]bool // In-memory visited check for this run
	maxInMem     int             // Maximum URLs to keep in the BFS queue
	allowedTLDs  map[string]bool // Optional: Allowed TLDs
	mu           sync.Mutex      // Protects shared resources
}

// NewCrawler initializes a new Crawler instance.
func NewCrawler(db *sql.DB, storeImages, skipHTML, skipImages bool, maxInMem int, allowedTLDs []string) *Crawler {
	tldMap := make(map[string]bool)
	for _, tld := range allowedTLDs {
		tldMap[strings.ToLower(tld)] = true
	}
	return &Crawler{
		db:           db,
		storeImages:  storeImages,
		skipHTML:     skipHTML,
		skipImages:   skipImages,
		baseDomains:  make(map[string]bool),
		visitedLinks: make(map[string]bool),
		maxInMem:     maxInMem,
		allowedTLDs:  tldMap,
	}
}

// InitDB creates the necessary tables if they don't already exist.
func (c *Crawler) InitDB() error {
	urlsTable := `
	CREATE TABLE IF NOT EXISTS crawled_urls (
		id SERIAL PRIMARY KEY,
		url TEXT NOT NULL UNIQUE,
		html_hash TEXT,
		html_content TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`

	imagesTable := `
	CREATE TABLE IF NOT EXISTS crawled_images (
		id SERIAL PRIMARY KEY,
		image_url TEXT NOT NULL UNIQUE,
		image_data BYTEA,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`

	if _, err := c.db.Exec(urlsTable); err != nil {
		return err
	}
	if _, err := c.db.Exec(imagesTable); err != nil {
		return err
	}
	return nil
}

// isURLInDB checks if a URL is already in the crawled_urls table.
func (c *Crawler) isURLInDB(u string) bool {
	query := `SELECT EXISTS(SELECT 1 FROM crawled_urls WHERE url = $1)`
	var exists bool
	err := c.db.QueryRow(query, u).Scan(&exists)
	if err != nil {
		fmt.Println("Error checking URL in database:", err)
		return false
	}
	return exists
}

// isImageVisited checks if an image URL is already in the crawled_images table.
func (c *Crawler) isImageVisited(imageURL string) bool {
	query := `SELECT EXISTS(SELECT 1 FROM crawled_images WHERE image_url = $1)`
	var exists bool
	err := c.db.QueryRow(query, imageURL).Scan(&exists)
	if err != nil {
		fmt.Println("Error checking image URL in database:", err)
	}
	return exists
}

// StoreCrawledData inserts URL data into crawled_urls (unless already present).
func (c *Crawler) StoreCrawledData(url, hash, htmlContent string) error {
	// Double-check if it's in DB to avoid duplicates
	if c.isURLInDB(url) {
		fmt.Printf("Already stored in DB: %s\n", url)
		return nil
	}
	insert := `INSERT INTO crawled_urls (url, html_hash, html_content) VALUES ($1, $2, $3) ON CONFLICT (url) DO NOTHING`
	_, err := c.db.Exec(insert, url, hash, htmlContent)
	return err
}

// StoreImageData inserts the image into crawled_images, skipping if it's already there.
func (c *Crawler) StoreImageData(imageURL string, imageData []byte) error {
	if c.isImageVisited(imageURL) {
		fmt.Printf("Skipping already stored image: %s\n", imageURL)
		return nil
	}
	insert := `INSERT INTO crawled_images (image_url, image_data) VALUES ($1, $2) ON CONFLICT (image_url) DO NOTHING`
	_, err := c.db.Exec(insert, imageURL, imageData)
	return err
}

// Crawl performs a breadth-first search (BFS) crawl starting from startURL up to the specified depth.
func (c *Crawler) Crawl(startURL string, depth int) {
	type queueItem struct {
		url   string
		depth int
	}
	queue := []queueItem{{url: startURL, depth: depth}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:] // Pop from front

		if item.depth < 0 {
			continue
		}

		// If we've seen it in this run or it's in the DB, skip
		if c.visitedLinks[item.url] || c.isURLInDB(item.url) {
			continue
		}

		// Mark as visited in this run
		c.visitedLinks[item.url] = true

		// Extract base domain
		baseDomain, err := c.getBaseDomain(item.url)
		if err != nil {
			fmt.Printf("Error extracting base domain from %s: %v\n", item.url, err)
			continue
		}

		// Optional: Check if the TLD is allowed
		if len(c.allowedTLDs) > 0 {
			tld := getTLD(baseDomain)
			if !c.allowedTLDs[strings.ToLower(tld)] {
				fmt.Printf("Skipping URL with disallowed TLD: %s\n", item.url)
				continue
			}
		}

		// Check if the base domain is already tracked
		if _, exists := c.baseDomains[baseDomain]; !exists {
			c.baseDomains[baseDomain] = true
		} else {
			// If the base domain is already tracked and we're skipping HTML, continue
			if c.skipHTML {
				fmt.Printf("Skipping already tracked base domain: %s\n", baseDomain)
				continue
			}
		}

		fmt.Printf("Crawling: %s (depth=%d)\n", item.url, item.depth)

		if c.skipHTML {
			// If skipping HTML, just store the URL and continue
			if err := c.StoreCrawledData(item.url, "", ""); err != nil {
				fmt.Printf("Error storing crawled data for %s: %v\n", item.url, err)
			}
			continue
		}

		var htmlContent string
		// Step 1: Try simple HTTP GET request
		htmlContent, err = c.simpleFetch(item.url)
		if err != nil {
			fmt.Printf("Error fetching URL (%s): %v\n", item.url, err)
			continue
		}

		links := c.extractLinks([]byte(htmlContent), item.url)
		if len(links) == 0 {
			// Step 2: If no links found, use Chromedp to render the page
			htmlContent, err = c.renderFetch(item.url)
			if err != nil {
				fmt.Printf("Error rendering URL (%s): %v\n", item.url, err)
				continue
			}
			links = c.extractLinks([]byte(htmlContent), item.url)
		}

		if len(htmlContent) > 0 {
			elapsed := time.Since(time.Now()) // Not accurate since time.Now() was just called
			fmt.Printf("Fetched %d bytes from %s in %v\n", len(htmlContent), item.url, elapsed)
		}

		// Store the crawled page in the DB
		hash := sha256.Sum256([]byte(htmlContent))
		hashStr := fmt.Sprintf("%x", hash)
		if err := c.StoreCrawledData(item.url, hashStr, htmlContent); err != nil {
			fmt.Printf("Error storing crawled data for %s: %v\n", item.url, err)
		}

		// If storing images, parse & store them
		if c.storeImages && !c.skipImages {
			c.saveImages([]byte(htmlContent), item.url)
		}

		// Extract links to add to the queue
		fmt.Printf("Found %d links on %s\n", len(links), item.url)
		nextDepth := item.depth - 1
		for _, link := range links {
			// Extract base domain of the link
			linkBaseDomain, err := c.getBaseDomain(link)
			if err != nil {
				continue
			}

			// Optional: Check if the TLD is allowed
			if len(c.allowedTLDs) > 0 {
				tld := getTLD(linkBaseDomain)
				if !c.allowedTLDs[strings.ToLower(tld)] {
					continue // Skip if TLD is not allowed
				}
			}

			// Skip if already visited or in the DB
			if c.visitedLinks[link] || c.isURLInDB(link) {
				continue
			}

			// Enqueue only if it's a new base domain
			if !c.baseDomains[linkBaseDomain] {
				c.baseDomains[linkBaseDomain] = true
				if len(queue) < c.maxInMem {
					queue = append(queue, queueItem{url: link, depth: nextDepth})
				} else {
					fmt.Printf("Queue is at capacity (%d). Skipping link: %s\n", c.maxInMem, link)
				}
			}
		}
	}
}

// simpleFetch uses a simple HTTP GET request to fetch the HTML content.
func (c *Crawler) simpleFetch(targetURL string) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Get(targetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-OK HTTP status: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// renderFetch uses Chromedp to render the page and fetch the HTML content.
func (c *Crawler) renderFetch(targetURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Initialize Chromedp context
	chromeCtx, chromeCancel := chromedp.NewContext(ctx)
	defer chromeCancel()

	var htmlContent string
	err := chromedp.Run(
		chromeCtx,
		chromedp.Navigate(targetURL),
		// Wait until the body element is ready
		chromedp.WaitReady("body", chromedp.ByQuery),
		// Execute scrolling with enhanced JavaScript
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Define a JavaScript function to scroll safely
			scrollScript := `
				(function() {
					try {
						let totalHeight = 0;
						let distance = 1000;
						let timer = setInterval(() => {
							if (document.body) {
								window.scrollBy(0, distance);
								totalHeight += distance;

								// If we've scrolled past the scrollHeight, clear the interval
								if (totalHeight >= document.body.scrollHeight) {
									clearInterval(timer);
								}
							}
						}, 1000);
					} catch (e) {
						console.error("Scrolling error:", e);
					}
				})();
			`
			return chromedp.Evaluate(scrollScript, nil).Do(ctx)
		}),
		// Wait additional time to allow lazy-loaded content to load
		chromedp.Sleep(5*time.Second),
		// Get the outer HTML
		chromedp.OuterHTML("html", &htmlContent),
	)
	if err != nil {
		return "", err
	}
	return htmlContent, nil
}

// extractLinks parses the HTML content and extracts all <a href="..."> links.
func (c *Crawler) extractLinks(body []byte, baseURL string) []string {
	var links []string
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		fmt.Printf("Error parsing HTML for %s: %v\n", baseURL, err)
		return links
	}

	var traverse func(*html.Node)
	traverse = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "a" {
			for _, attr := range node.Attr {
				if attr.Key == "href" {
					link := c.normalizeURL(attr.Val, baseURL)
					if link != "" {
						links = append(links, link)
					}
					break
				}
			}
		}
		// Continue traversing child nodes
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			traverse(child)
		}
	}
	traverse(doc)
	return links
}

// normalizeURL resolves relative links against the base URL and ensures they are valid HTTP/HTTPS URLs.
func (c *Crawler) normalizeURL(link, baseURL string) string {
	parsedURL, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return ""
	}
	if parsedURL.Scheme == "mailto" || parsedURL.Scheme == "javascript" || parsedURL.Scheme == "data" {
		return ""
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	resolvedURL := base.ResolveReference(parsedURL)

	// Remove URL fragments
	resolvedURL.Fragment = ""

	// Optionally, you can also normalize the URL by removing or sorting query parameters
	return resolvedURL.String()
}

// saveImages finds <img src="..."> tags, downloads them (or decodes data URIs), and stores them in the DB.
func (c *Crawler) saveImages(body []byte, baseURL string) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		fmt.Printf("Error parsing HTML for images on page (%s): %v\n", baseURL, err)
		return
	}
	var traverse func(*html.Node)
	traverse = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "img" {
			for _, attr := range node.Attr {
				if attr.Key == "src" {
					imageURL := strings.TrimSpace(attr.Val)
					if imageURL == "" {
						continue
					}
					if strings.HasPrefix(imageURL, "data:") {
						// Data URI
						parts := strings.SplitN(imageURL, ",", 2)
						if len(parts) == 2 && strings.HasPrefix(parts[0], "data:image/") {
							// Determine if it's base64 encoded
							isBase64 := strings.Contains(parts[0], "base64")
							var imageData []byte
							var decErr error
							if isBase64 {
								imageData, decErr = base64.StdEncoding.DecodeString(parts[1])
							} else {
								imageData = []byte(parts[1])
								decErr = nil
							}
							if decErr == nil {
								c.StoreImageData(imageURL, imageData)
							} else {
								fmt.Printf("Error decoding data URI for image on %s: %v\n", baseURL, decErr)
							}
						}
					} else {
						// Normal external image
						imageURL = c.normalizeURL(imageURL, baseURL)
						if imageURL != "" {
							c.downloadAndStoreImage(imageURL)
						}
					}
					break
				}
			}
		}
		// Continue traversing child nodes
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			traverse(child)
		}
	}
	traverse(doc)
}

// downloadAndStoreImage downloads the image from the given URL and stores it in the DB.
func (c *Crawler) downloadAndStoreImage(imageURL string) {
	if c.isImageVisited(imageURL) {
		fmt.Printf("Skipping already stored image: %s\n", imageURL)
		return
	}
	resp, err := http.Get(imageURL)
	if err != nil {
		fmt.Printf("Error downloading image (%s): %v\n", imageURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Non-OK HTTP status for image (%s): %s\n", imageURL, resp.Status)
		return
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading image data (%s): %v\n", imageURL, err)
		return
	}
	if len(data) == 0 {
		fmt.Printf("Empty image data for (%s). Skipping.\n", imageURL)
		return
	}
	if err := c.StoreImageData(imageURL, data); err != nil {
		fmt.Printf("Error storing image data (%s): %v\n", imageURL, err)
	}
}

// getTLD extracts the TLD from the base domain.
func getTLD(baseDomain string) string {
	parts := strings.Split(baseDomain, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

// getBaseDomain extracts the eTLD+1 from a URL.
func (c *Crawler) getBaseDomain(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	baseDomain, err := publicsuffix.EffectiveTLDPlusOne(parsedURL.Hostname())
	if err != nil {
		return "", err
	}
	return baseDomain, nil
}

func main() {
	// Define command-line flags
	storeImagesFlag := flag.Bool("store-images", true, "Set to false to skip storing images")
	skipHTMLFlag := flag.Bool("skip-html", false, "Set to true to skip downloading HTML content")
	skipImagesFlag := flag.Bool("skip-images", false, "Set to true to skip downloading images")
	startURL := flag.String("url", "https://example.com", "The starting URL for crawling")
	depth := flag.Int("depth", 2, "How deep (distance from the start URL)")
	maxInMem := flag.Int("max-in-mem", 1000, "Maximum URLs to keep in BFS queue at once")
	tldList := flag.String("allowed-tlds", "com,org,net", "Comma-separated list of allowed TLDs (e.g., com,org,net)")

	// PostgreSQL connection flags
	dbHost := flag.String("dbhost", "localhost", "Database host")
	dbPort := flag.Int("dbport", 5432, "Database port")
	dbUser := flag.String("dbuser", "postgres", "Database user")     // Default user
	dbPassword := flag.String("dbpassword", "", "Database password") // No password
	dbName := flag.String("dbname", "crawler", "Database name")      // Ensure 'crawler' database exists
	dbSSLMode := flag.String("sslmode", "disable", "SSL mode")       // Disable SSL for local connections

	flag.Parse()

	// Parse allowed TLDs
	var allowedTLDs []string
	if *tldList != "" {
		allowedTLDs = strings.Split(*tldList, ",")
		for i, tld := range allowedTLDs {
			allowedTLDs[i] = strings.TrimSpace(tld)
		}
	}

	// Construct PostgreSQL connection string
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		*dbHost, *dbPort, *dbUser, *dbPassword, *dbName, *dbSSLMode)

	// Open the PostgreSQL DB
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	// Verify connection
	err = db.Ping()
	if err != nil {
		fmt.Println("Error connecting to the database:", err)
		return
	}

	// Create the crawler
	crawler := NewCrawler(db, *storeImagesFlag, *skipHTMLFlag, *skipImagesFlag, *maxInMem, allowedTLDs)
	if err := crawler.InitDB(); err != nil {
		fmt.Println("Error initializing database:", err)
		return
	}

	// Start BFS crawl
	crawler.Crawl(*startURL, *depth)
}
