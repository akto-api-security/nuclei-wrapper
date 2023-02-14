package main

import (
	"context"
	"fmt"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/ratelimit"
)

func main() {

	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()

	defaultOpts := types.DefaultOptions()

	defaultOpts.StoreResponse = true
	defaultOpts.JSONRequests = true
	defaultOpts.StatsJSON = true
	defaultOpts.Timeout = 2

	protocolstate.Init(defaultOpts)
	protocolinit.Init(defaultOpts)

	//defaultOpts.ExcludeTags = config.ReadIgnoreFile().Tags

	defaultOpts.Vars = goflags.RuntimeMap{}
	defaultOpts.CustomHeaders = goflags.StringSlice{}

	var url string
	var templateLink string
	var storeRespDir string
	var outputFilesDir string
	var configDir string

	for index, element := range os.Args {
		if index == 0 {
			continue
		}

		if string(element[0]) != "-" {
			continue
		}

		value := os.Args[index+1]

		switch element {
		case "-u":
			url = value
		case "-t":
			templateLink = value
		case "-h":
			vList := strings.Split(value, ":")
			v := strings.Join(vList[1:], ":")
			if v[0] == '"' && v[len(v)-1] == '"' {
				defaultOpts.CustomHeaders.Set(vList[0] + ":" + v[1:len(v)-1])
			} else {
				defaultOpts.CustomHeaders.Set(value)
			}
		case "-v":
			defaultOpts.Vars.Set(value)
		case "-store-resp-dir":
			storeRespDir = value
		case "-output-files-dir":
			outputFilesDir = value
		case "-template-dir":
			configDir = value
		}
	}

	if url == "" {
		fmt.Println("Invalid url")
		return
	}

	defaultOpts.Templates = goflags.StringSlice{templateLink}
	outputWriter, _ := output.NewStandardWriter(true, true, true, true, true, true, true, outputFilesDir+"/main.txt", outputFilesDir+"/trace.txt", outputFilesDir+"/error.txt", storeRespDir)

	interactOpts := interactsh.NewDefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		log.Fatalf("Could not create interact client: %s\n", err)
	}
	defer interactClient.Close()

	home, _ := os.UserHomeDir()
	catalog := disk.NewCatalog(path.Join(home, "nuclei-templates"))
	executerOpts := protocols.ExecuterOptions{
		Output:          outputWriter,
		Options:         defaultOpts,
		Progress:        mockProgress,
		Catalog:         catalog,
		IssuesClient:    reportingClient,
		RateLimiter:     ratelimit.New(context.Background(), 150, time.Second),
		Interactsh:      interactClient,
		HostErrorsCache: cache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
	}
	engine := core.New(defaultOpts)
	engine.SetExecuterOptions(executerOpts)

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		log.Fatalf("Could not create workflow loader: %s\n", err)
	}
	executerOpts.WorkflowLoader = workflowLoader

	config.SetCustomConfigDirectory(configDir)
	configObject, err := config.ReadConfiguration()
	if err != nil {
		log.Fatalf("Could not read config: %s\n", err)
	}
	store, err := loader.New(loader.NewConfig(defaultOpts, configObject, catalog, executerOpts))
	if err != nil {
		log.Fatalf("Could not create loader client: %s\n", err)
	}
	store.Load()

	input := &inputs.SimpleInputProvider{Inputs: []*contextargs.MetaInput{{Input: url}}}
	engine.Execute(store.Templates(), input)
	engine.WorkPool().Wait() // Wait for the scan to finish

}
