package scan

import (
	"context"
	"fmt"
	networkscanner "github.com/iangregsondev/naabuerr/entities"
	"github.com/iangregsondev/naabuerr/handlers/scan"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

type Service struct {
	logger           logrus.FieldLogger
	scanHandler      *scan.Scan
	scanResultCh     <-chan networkscanner.ScanResult
	discoverResultCh <-chan networkscanner.DiscoverResult
}

func NewService(
	logger logrus.FieldLogger, scanHandler *scan.Scan, scanResultCh <-chan networkscanner.ScanResult, discoverRResultCh <-chan networkscanner.DiscoverResult,
) *Service {
	return &Service{
		logger:           logger,
		scanHandler:      scanHandler,
		scanResultCh:     scanResultCh,
		discoverResultCh: discoverRResultCh,
	}
}

func (s *Service) Scan(ctx context.Context, data networkscanner.ScanCommandData) {
	if s.scanHandler.ScanInProgress() {
		s.logger.Warning("scanner is currently busy, ignoring scan request")
		return
	}

	go func() {
		s.scanHandler.Scan(ctx, data)
	}()
}

func (s *Service) Discover(ctx context.Context, data networkscanner.DiscoverCommandData) {
	if s.scanHandler.ScanInProgress() {
		s.logger.Warning("scanner is currently busy, ignoring discover request")
		return
	}

	go func() {
		s.scanHandler.Discover(ctx, data)
	}()
}

// Star this is a temporary method utilizing the imports - it will change!
func (s *Service) Start(ctx context.Context, wg *sync.WaitGroup) error {
	defer wg.Done()
	s.logger.Info("Starting listeners for scan functionality...	")

	// Set up the global logger that is used by naabu and nuclei to get logs in json format
	gologger.DefaultLogger.SetFormatter(&formatter.JSON{})

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(30 * time.Second):
			fmt.Println("Tick (every 30 seconds).....")

		case result := <-s.discoverResultCh:
			if result.Error != nil {
				fmt.Println("Error: ", result.Error)
				continue
			}
			// TODO These need to be published
			fmt.Println("Here are the results from discover ", result)

		case result := <-s.scanResultCh:
			if result.Error != nil {
				fmt.Println("Error: ", result.Error)
				continue
			}
			// TODO These need to be published
			fmt.Println("Here are the results from scan ", result)
		}
	}

}
