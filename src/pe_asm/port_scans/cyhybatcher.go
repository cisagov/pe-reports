//package main
//
//import (
//	"context"
//	"encoding/json"
//	"fmt"
//	"go.mongodb.org/mongo-driver/bson"
//	"go.mongodb.org/mongo-driver/mongo"
//	"go.mongodb.org/mongo-driver/mongo/options"
//	"io/ioutil"
//	"log"
//	"sync"
//	"time"
//)
//
//type Config struct {
//	Host     string `json:"host"`
//	User     string `json:"user"`
//	Password string `json:"password"`
//	Port     string `json:"port"`
//	Database string `json:"database"`
//}
//
//const (
//	chunkSize  = 10000
//	oneDayAgo  = 1 * 24 * time.Hour
//	numWorkers = 8
//)
//
//func readConfig(filename string) (Config, error) {
//	var config Config
//	data, err := ioutil.ReadFile(filename)
//	if err != nil {
//		return config, err
//	}
//
//	err = json.Unmarshal(data, &config)
//	return config, err
//}
//
//func mongoConnect(config Config) (*mongo.Database, error) {
//	connectionString := fmt.Sprintf("mongodb://%s:%s@%s:%s/%s",
//		config.User,
//		config.Password,
//		config.Host,
//		config.Port,
//		config.Database)
//	client, err := mongo.NewClient(options.Client().ApplyURI(connectionString))
//	if err != nil {
//		return nil, err
//	}
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//
//	err = client.Connect(ctx)
//	if err != nil {
//		return nil, err
//	}
//
//	return client.Database(config.Database), nil
//}
//
//func worker(ctx context.Context, id int, in <-chan bson.M,
//	out chan<- []bson.M,
//	wg *sync.WaitGroup) {
//	defer wg.Done()
//
//	var documents []bson.M
//
//	for document := range in {
//		documents = append(documents, document)
//
//		if len(documents) == chunkSize {
//			out <- documents
//			documents = nil
//		}
//	}
//
//	if len(documents) > 0 {
//		out <- documents
//	}
//}
//
//// getCyhyPortScans retrieves CyHy port scans and processes them in parallel.
//func getCyhyPortScans(staging bool, config Config, start time.Time, end time.Time) [][]bson.M {
//	// Connect to the CyHy database and fetch all request data
//	cyhyDB, err := mongoConnect(config)
//	if err != nil {
//		log.Fatalf("Failed to connect to MongoDB: %v", err)
//	}
//
//	collection := cyhyDB.Collection("port_scans")
//
//	// Only query documents that are a month old
//	//start := time.Now()
//	query := bson.M{"time": bson.M{"$gt": start, "$lte": end}}
//	cursor, err := collection.Find(context.Background(), query)
//	if err != nil {
//		log.Fatalf("Failed to find documents: %v", err)
//	}
//	elapsed := time.Since(start)
//	fmt.Printf("Network operation took %v\n", elapsed)
//	defer cursor.Close(context.Background())
//
//	// Split the cursor into chunks and process each chunk in a separate goroutine
//	portScansTotal, err := collection.CountDocuments(context.Background(), query)
//	if err != nil {
//		log.Fatalf("Failed to count documents: %v", err)
//	}
//	fmt.Printf("%d total documents.\n", portScansTotal)
//
//	documentCh := make(chan bson.M)
//	batchCh := make(chan []bson.M, numWorkers)
//	var wg sync.WaitGroup
//
//	// Start worker goroutines
//	for i := 0; i < numWorkers; i++ {
//		wg.Add(1)
//		go worker(context.Background(), i, documentCh, batchCh, &wg)
//	}
//
//	// Send documents to workers
//	go func() {
//		for cursor.Next(context.Background()) {
//			var document bson.M
//			if err := cursor.Decode(&document); err != nil {
//				log.Fatalf("Failed to decode document: %v", err)
//			}
//			documentCh <- document
//		}
//		close(documentCh)
//	}()
//
//	// Collect batches from workers
//	go func() {
//		wg.Wait()
//		close(batchCh)
//	}()
//
//	var (
//		batches    [][]bson.M
//		batchCount int
//		mu         sync.Mutex
//	)
//
//	start = time.Now()
//
//	// Process each batch concurrently
//	for batch := range batchCh {
//		wg.Add(1)
//		go func(batch []bson.M) {
//			defer wg.Done()
//
//			mu.Lock()
//			batches = append(batches, batch)
//			batchCount++
//			fmt.Printf("%d batch created and added to batches.\n", batchCount)
//			mu.Unlock()
//		}(batch)
//	}
//
//	wg.Wait()
//
//	elapsed = time.Since(start)
//	fmt.Printf("Batch %d processsed in %s\n", batchCount, elapsed)
//
//	fmt.Printf("%d batches will be run.\n", len(batches))
//
//	//Process batches in parallel
//	//var wg sync.WaitGroup
//	for _, batch := range batches {
//		wg.Add(1)
//		go func(batch []bson.M) {
//			defer wg.Done()
//			printWg := sync.WaitGroup{}
//			printWg.Add(1)
//			start := time.Now()
//			//go func() {
//			//	defer printWg.Done()
//			//
//			//	fmt.Println(batch)
//			//}()
//			//processBatch(staging, batch)
//			elapsed := time.Since(start)
//			printWg.Wait()
//			fmt.Printf("Batch %d processed in %s\n",
//				batchCount,
//				elapsed)
//
//		}(batch)
//	}
//	wg.Wait()
//
//	// Close the database connections
//	// This will be automatically done when the program
//	//exits or the mongo.Client instance is garbage collected
//	return batches
//}
//
//func main() {
//	config, err := readConfig("src/config.json")
//	if err != nil {
//		log.Fatalf("Failed to read config file: %v", err)
//	}
//
//	db, err := mongoConnect(config)
//	if err != nil {
//		log.Fatalf("Failed to connect to MongoDB: %v", err)
//	}
//	fmt.Println("Connected to MongoDB:", db)
//
//	// Define the time ranges to retrieve port scans for
//	timeRanges := []struct {
//		start time.Time
//		end   time.Time
//	}{
//		{start: time.Now().Add(-9 * oneDayAgo), end: time.Now()},
//		//{start: time.Now().Add(-18 * oneDayAgo), end: time.Now().Add(-9 * oneDayAgo)},
//		//{start: time.Now().Add(-30 * oneDayAgo), end: time.Now().Add(-18 * oneDayAgo)},
//	}
//
//	// Create a wait group for the goroutines
//	var wg sync.WaitGroup
//
//	// Loop over the time ranges and retrieve port scans for each time range concurrently
//	for i, tr := range timeRanges {
//		fmt.Printf("Getting port scans for time range %d: %v - %v\n", i+1, tr.start, tr.end)
//		wg.Add(1)
//		go func(tr struct{ start, end time.Time }) {
//			defer wg.Done()
//			getCyhyPortScans(false, config, tr.start, tr.end)
//		}(tr)
//	}
//
//	// Wait for all goroutines to finish
//	wg.Wait()
//}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

type Config struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	Port     string `json:"port"`
	Database string `json:"database"`
}

const (
	chunkSize  = 100000000
	oneDayAgo  = 1 * 24 * time.Hour
	numWorkers = 8
)

func readConfig(filename string) (Config, error) {
	var config Config
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return config, err
	}

	err = json.Unmarshal(data, &config)
	return config, err
}

func mongoConnect(config Config) (*mongo.Database, error) {
	connectionString := fmt.Sprintf("mongodb://%s:%s@%s:%s/%s",
		config.User,
		config.Password,
		config.Host,
		config.Port,
		config.Database)
	client, err := mongo.NewClient(options.Client().ApplyURI(connectionString))
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	return client.Database(config.Database), nil
}

func worker(ctx context.Context, id int, in <-chan bson.M,
	out chan<- []bson.M,
	wg *sync.WaitGroup) {
	defer wg.Done()

	var documents []bson.M

	for document := range in {
		documents = append(documents, document)

		if len(documents) == chunkSize {
			out <- documents
			documents = nil
		}
	}

	if len(documents) > 0 {
		out <- documents
	}
}

// getCyhyPortScans retrieves CyHy port scans and processes them in parallel.
func getCyhyPortScans(staging bool, config Config, start time.Time, end time.Time, owner string) [][]bson.M {
	// Connect to the CyHy database and fetch all request data
	cyhyDB, err := mongoConnect(config)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	collection := cyhyDB.Collection("port_scans")

	// Only query documents that are a month old
	//start := time.Now()
	query := bson.M{"owner": owner, "time": bson.M{"$gt": start, "$lte": end}}
	//fmt.Printf("Query: %v\n", query)
	cursor, err := collection.Find(context.Background(), query)
	if err != nil {
		log.Fatalf("Failed to find documents: %v", err)
	}
	//elapsed := time.Since(start)
	//fmt.Printf("Network operation took %v\n", elapsed)
	//fmt.Printf("The owner is %s.\n", owner)
	defer cursor.Close(context.Background())

	// Split the cursor into chunks and process each chunk in a separate goroutine
	//portScansTotal, err := collection.CountDocuments(context.Background(), query)
	//if err != nil {
	//	log.Fatalf("Failed to count documents: %v", err)
	//}
	//fmt.Printf("%d total documents.\n", portScansTotal)

	documentCh := make(chan bson.M)
	batchCh := make(chan []bson.M, numWorkers)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(context.Background(), i, documentCh, batchCh, &wg)
	}

	// Send documents to workers
	go func() {
		for cursor.Next(context.Background()) {
			var document bson.M
			if err := cursor.Decode(&document); err != nil {
				log.Fatalf("Failed to decode document: %v", err)
			}
			documentCh <- document
		}
		close(documentCh)
	}()

	// Collect batches from workers
	go func() {
		wg.Wait()
		close(batchCh)
	}()

	var (
		batches    [][]bson.M
		batchCount int
	)

	start = time.Now()

	//for batch := range batchCh {
	//	batches = append(batches, batch)
	//	batchCount++
	//	fmt.Printf("%d batches created.\n", batchCount)
	//}
	// Process each batch concurrently
	for batch := range batchCh {
		wg.Add(1)
		go func(batch []bson.M) {
			defer wg.Done()

			//mu.Lock()
			batches = append(batches, batch)
			batchCount++
			//fmt.Printf("%d batch created and added to batches.\n", batchCount)
			//mu.Unlock()
		}(batch)
	}

	wg.Wait()

	//elapsed = time.Since(start)
	//fmt.Printf("Batch %d processsed in %s\n", batchCount, elapsed)

	//fmt.Printf("%d batches will be run.\n", len(batches))

	return batches

	//Process batches in parallel
	//var wg sync.WaitGroup
	//for _, batch := range batches {
	//	wg.Add(1)
	//	go func(batch []bson.M) {
	//		defer wg.Done()
	//		printWg := sync.WaitGroup{}
	//		printWg.Add(1)
	//		start := time.Now()
	//		go func() {
	//			defer printWg.Done()
	//
	//			fmt.Println(batch)
	//		}()
	//		//processBatch(staging, batch)
	//		elapsed := time.Since(start)
	//		printWg.Wait()
	//		fmt.Printf("Batch %d processed in %s\n",
	//			batchCount,
	//			elapsed)
	//
	//	}(batch)
	//}
	//wg.Wait()

	// Close the database connections
	// This will be automatically done when the program
	//exits or the mongo.Client instance is garbage collected

}

func main() {
	args := os.Args[1:]

	if len(args) < 3 {
		fmt.Println("Error: Please provide start and end days as arguments.")
		os.Exit(1)
	}

	// Convert the first argument to an integer
	startDaysAgo, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("Error: Argument %s is not a valid integer\n", args[0])
		os.Exit(1)
	}

	// Convert the second argument to an integer
	endDaysAgo, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Printf("Error: Argument %s is not a valid integer\n", args[1])
		os.Exit(1)
	}

	//Add owner as third argument
	owner := args[2]

	startTM := time.Now().Add(-time.Duration(startDaysAgo) * oneDayAgo)
	endTM := time.Now().Add(-time.Duration(endDaysAgo) * oneDayAgo)

	config, err := readConfig("./src/pe_asm/port_scans/config.json")
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	db, err := mongoConnect(config)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	fmt.Println("Connected to MongoDB:", db)

	//getCyhyPortScans(false, config, startTM, endTM)

	jsonData, err := json.Marshal(getCyhyPortScans(false, config, startTM, endTM, owner))
	if err != nil {
		fmt.Fprint(os.Stderr, "Error converting data to JSON:", err)
		os.Exit(1)
	}

	// Print the JSON string to stdout
	fmt.Println(string(jsonData))

}
