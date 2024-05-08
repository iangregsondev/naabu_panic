package main

import (
	"context"
	"fmt"
	networkscanner "github.com/iangregsondev/naabuerr/entities"
	scanhandler "github.com/iangregsondev/naabuerr/handlers/scan"
	"github.com/iangregsondev/naabuerr/services/scan"
	"github.com/sirupsen/logrus"
	"os"
	"sync"
)

func main() {
	// Create a new instance of the logger
	logger := logrus.New()

	ctx := context.Background()

	// Set the Output, which is where the logs will be written to.
	logger.Out = os.Stdout

	// Set the log level, which controls what level of logs will be logged.
	logger.SetLevel(logrus.DebugLevel)

	logger.Info("Starting network scanner...")

	// Custom writer is used to collect log data from nuclei and pass into our custom logger
	customWriter := scanhandler.NewCustomWriter(logger)

	scanResultCh := make(chan networkscanner.ScanResult, 3)
	discoverResultCh := make(chan networkscanner.DiscoverResult, 3)

	// Scan handler handles all discovery and scanning functionality for the network scanner
	scanHandler := scanhandler.New(logger, customWriter, scanResultCh, discoverResultCh)

	// Scan service is the service that will be called by the command service, it has access to the scan handler
	scanService := scan.NewService(logger, scanHandler, scanResultCh, discoverResultCh)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go scanService.Start(ctx, &wg)

	scanService.Scan(
		ctx, networkscanner.ScanCommandData{
			ID:     "1234",
			Ranges: []string{"scanme.sh"},
			// Tags:   []string{"tag1", "tag2"},
		},
	)

	wg.Wait()

	fmt.Println("Goodbye!")
}
