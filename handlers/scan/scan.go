package scan

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"

	networkscanner "github.com/iangregsondev/naabuerr/entities"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	parsers "github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/ratelimit"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

type SourceLogger string

const (
	SourceLoggerNaabu  = SourceLogger("Naabu")
	SourceLoggerNuclei = SourceLogger("Nuclei")
)

type Scan struct {
	logger           logrus.FieldLogger
	customWriter     *CustomWriter
	scanResultCh     chan<- networkscanner.ScanResult
	discoverResultCh chan<- networkscanner.DiscoverResult
	scanInProgress   *atomic.Bool
}

func New(
	logger logrus.FieldLogger, customWriter *CustomWriter,
	scanResultCh chan<- networkscanner.ScanResult,
	discoverResultCh chan<- networkscanner.DiscoverResult,

) *Scan {
	return &Scan{
		logger:           logger,
		customWriter:     customWriter,
		scanResultCh:     scanResultCh,
		discoverResultCh: discoverResultCh,
		scanInProgress:   new(atomic.Bool),
	}
}

func (s *Scan) ScanInProgress() bool {
	return s.scanInProgress.Load()
}

func (s *Scan) Discover(ctx context.Context, data networkscanner.DiscoverCommandData) {
	s.scanInProgress.Store(true)

	defer func() {
		s.scanInProgress.Store(false)
	}()

	// Set writer to our custom writer that also wraps the source logger info
	gologger.DefaultLogger.SetWriter(s.customWriter.GetWriter(ctx, string(SourceLoggerNaabu)))

	results := make([]string, 0)

	options := runner.Options{
		// TODO These are static right now, but we may want to provide them as options
		Verbose: false,
		Debug:   false,
		Silent:  false,
		// END TODO
		Host:     data.Targets,
		ScanType: data.ScanType,
		OnResult: func(hr *result.HostResult) {
			for _, port := range hr.Ports {
				formatted := fmt.Sprintf("%s:%d", hr.Host, port.Port)
				results = append(results, formatted)
			}
		},
		TopPorts: data.TopPorts,
		// TODO These are static right now, but we may want to provide them as options
		// This will be done in another PR once I understand there impact :-)
		Threads: 25,
		Rate:    1000,
		Timeout: 1000,
		Retries: 3,
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		s.discoverResultCh <- networkscanner.DiscoverResult{
			DiscoverID: data.ID,
			Error:      fmt.Errorf("error creating runner: %w", err),
		}
		return
	}
	defer naabuRunner.Close()

	// err = naabuRunner.RunEnumeration()
	err = naabuRunner.RunEnumeration(ctx) // v2.3.0 but currently has an issue
	if err != nil {
		s.discoverResultCh <- networkscanner.DiscoverResult{
			DiscoverID: data.ID,
			Error:      fmt.Errorf("error running enumeration: %w", err),
		}
		return
	}

	s.discoverResultCh <- networkscanner.DiscoverResult{
		DiscoverID: data.ID,
		Results:    results,
	}
}

func (s *Scan) Scan(ctx context.Context, data networkscanner.ScanCommandData) {
	s.logger.Info("Starting Scan.....")
	s.scanInProgress.Store(true)

	defer func() {
		s.scanInProgress.Store(false)
		fmt.Println("Scan Completed.....")
	}()

	scanData := make([]networkscanner.ScanData, 0)

	// Set writer to our custom writer that also wraps the source logger info
	gologger.DefaultLogger.SetWriter(s.customWriter.GetWriter(ctx, string(SourceLoggerNuclei)))

	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "", true)
	defer reportingClient.Close()

	outputWriter := testutils.NewMockOutputWriter(true)
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		s.logger.Debug("an event has arrived, processing it.....")
		scanData = append(
			scanData, networkscanner.ScanData{
				TemplateID:  event.TemplateID,
				Name:        event.Info.Name,
				Description: event.Info.Description,
				Type:        event.Type,
				Tags:        event.Info.Tags.ToSlice(),
				Host:        event.Host,
				Port:        event.Port,
			},
		)
	}

	defaultOpts := types.DefaultOptions()
	defaultOpts.UpdateTemplates = false
	defaultOpts.Silent = false
	defaultOpts.Verbose = false
	defaultOpts.Debug = false

	err := protocolstate.Init(defaultOpts)
	if err != nil {
		s.scanResultCh <- networkscanner.ScanResult{
			ScanID: data.ID,
			Error:  fmt.Errorf("error initializing protocol state: %w", err),
		}
		return
	}
	err = protocolinit.Init(defaultOpts)
	if err != nil {
		s.scanResultCh <- networkscanner.ScanResult{
			ScanID: data.ID,
			Error:  fmt.Errorf("error initializing protocol init: %w", err),
		}
		return
	}

	defaultOpts.Tags = data.Tags

	interactOpts := interactsh.DefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		s.scanResultCh <- networkscanner.ScanResult{
			ScanID: data.ID,
			Error:  fmt.Errorf("error creating interact client: %w", err),
		}
		return
	}
	defer interactClient.Close()

	// home, _ := os.UserHomeDir()
	getwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory")
		return
	}

	cpath := filepath.Join(getwd, "rules")

	fmt.Println("Here is the catalog directory ", cpath)

	catalog := disk.NewCatalog(cpath)
	// catalog := disk.NewCatalog(filepath.Join(getwd, "nuclei-templates"))

	parser := templates.NewParser()
	executerOpts := protocols.ExecutorOptions{
		TemplatePath:    cpath,
		Output:          outputWriter,
		Options:         defaultOpts,
		Progress:        mockProgress,
		Catalog:         catalog,
		IssuesClient:    reportingClient,
		RateLimiter:     ratelimit.New(context.Background(), 150, time.Second),
		Interactsh:      interactClient,
		HostErrorsCache: cache,
		Colorizer:       aurora.NewAurora(false),
		ResumeCfg:       types.NewResumeCfg(),
		Parser:          parser,
	}
	engine := core.New(defaultOpts)
	engine.SetExecuterOptions(executerOpts)

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		s.scanResultCh <- networkscanner.ScanResult{
			ScanID: data.ID,
			Error:  fmt.Errorf("error creating workflow loader: %w", err),
		}
		return
	}

	executerOpts.WorkflowLoader = workflowLoader

	loaderConfig := loader.NewConfig(defaultOpts, catalog, executerOpts)

	store, err := loader.New(loaderConfig)
	if err != nil {
		s.scanResultCh <- networkscanner.ScanResult{
			ScanID: data.ID,
			Error:  fmt.Errorf("error creating loader client: %w", err),
		}
		return
	}

	store.Load()

	s.logger.Debug("total number of templates loaded: ", len(store.Templates()))

	inputArgs := make([]*contextargs.MetaInput, 0)

	for _, r := range data.Ranges {
		inputArgs = append(inputArgs, &contextargs.MetaInput{Input: r})
	}

	input := &provider.SimpleInputProvider{Inputs: inputArgs}

	egResult := engine.Execute(ctx, store.Templates(), input)

	if !egResult.Load() {
		s.scanResultCh <- networkscanner.ScanResult{
			ScanID: data.ID,
			Error:  fmt.Errorf("error executing engine"),
		}
		return
	}

	s.scanResultCh <- networkscanner.ScanResult{
		ScanID:   data.ID,
		ScanData: scanData,
	}
}
