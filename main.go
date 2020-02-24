package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	prom_config "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"golang.org/x/sync/errgroup"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

var (
	discoverTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_discover_total",
			Help: "The total number of HTTP discover calls.",
		},
		[]string{"url", "status"},
	)
)

func main() {
	var (
		config = kingpin.Flag("config", "discovery configuration file name.").Default("discover.yaml").String()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)

	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := promlog.New(promlogConfig)

	d, err := newFromFile(*config, logger)
	if err != nil {
		_ = level.Error(logger).Log("failed to create config", "error", err, "configFile", *config)

		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return d.run(ctx)
	})

	g.Go(func() error {
		<-signals
		cancel()
		return nil
	})

	if err := g.Wait(); err != nil {
		_ = level.Error(logger).Log("runtime error", "error", err)
	}
}

// Discovery is a collection of targets.
type Discovery struct {
	targets []*target
	logger  log.Logger
}

type target struct {
	request *http.Request
	client  *http.Client
	config  *discoverConfig
	logger  log.Logger
	url     string
}

type config struct {
	DiscoverConfigs []*discoverConfig `yaml:"discover_configs"`
}

type discoverConfig struct {
	URL              prom_config.URL              `yaml:"url"`
	RefreshInterval  model.Duration               `yaml:"refresh_interval,omitempty"`
	Timeout          model.Duration               `yaml:"timeout,omitempty"`
	File             string                       `yaml:"file"`
	HTTPClientConfig prom_config.HTTPClientConfig `yaml:",inline"`
}

func (c *discoverConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = discoverConfig{}

	type plain discoverConfig

	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	if err := c.HTTPClientConfig.Validate(); err != nil {
		return err
	}

	if c.URL.URL == nil {
		return errors.New("url is required")
	}

	if c.RefreshInterval == 0 {
		c.RefreshInterval = model.Duration(5 * time.Minute)
	}

	if c.Timeout == 0 {
		c.Timeout = model.Duration(time.Second * 10)
	}

	if c.File == "" {
		return errors.New("file is required")
	}

	return nil
}

func configFromFile(filename string) (*config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var c config

	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}

	return &c, nil
}

func newFromFile(filename string, logger log.Logger) (*Discovery, error) {
	cfg, err := configFromFile(filename)
	if err != nil {
		return nil, err
	}

	return newDiscovery(cfg, logger)
}

func newDiscovery(cfg *config, logger log.Logger) (*Discovery, error) {
	if logger == nil {
		logger = log.NewNopLogger()
	}

	d := &Discovery{
		logger: logger,
	}

	for _, c := range cfg.DiscoverConfigs {
		rt, err := prom_config.NewRoundTripperFromConfig(c.HTTPClientConfig, "discover", false)
		if err != nil {
			return nil, err
		}

		t := target{
			request: &http.Request{
				Method:     http.MethodGet,
				URL:        c.URL.URL,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Host:       c.URL.Host,
			},
			client: &http.Client{
				Transport: rt,
			},
			config: c,
			logger: log.With(logger, "url", c.URL.String()),
			url:    c.URL.String(),
		}

		d.targets = append(d.targets, &t)
	}

	return d, nil
}

func (d *Discovery) run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	for _, t := range d.targets {
		g.Go(func() error {
			// initial discovery
			err := t.discover(ctx)
			t.recordMetrics(err)

			tick := time.NewTicker(time.Duration(t.config.RefreshInterval))

			for {
				select {
				case <-ctx.Done():
					tick.Stop()
					return nil
				case <-tick.C:
					err := t.discover(ctx)
					t.recordMetrics(err)
				}
			}
		})
	}

	return g.Wait()
}

func (t *target) recordMetrics(err error) {
	status := "ok"

	if err != nil {
		status = "error"
		_ = level.Error(t.logger).Log("discovery failed", "error", err)
	}

	discoverTotal.WithLabelValues(t.url, status).Add(1)
}

// see https://prometheus.io/docs/prometheus/latest/configuration/configuration/#file_sd_config
type targetGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels,omitempty"`
}

func (t *target) discover(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(t.config.Timeout))
	defer cancel()

	req := t.request.WithContext(ctx)

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get url %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body %w", err)
	}

	var tgs []targetGroup

	// ensure it is valid json
	if err := json.Unmarshal(body, &tgs); err != nil {
		return fmt.Errorf("failed to parse response body %w", err)
	}

	data, err := json.Marshal(tgs)
	if err != nil {
		return fmt.Errorf("failed to marshal targetgroups %w", err)
	}

	if err := atomicWrite(t.config.File, 0644, data); err != nil {
		return fmt.Errorf("failed to write file %w", err)
	}

	return nil
}

func atomicWrite(filename string, mode os.FileMode, data []byte) error {
	dir, file := filepath.Split(filename)

	f, err := ioutil.TempFile(dir, ".tmp."+file)
	if err != nil {
		return err
	}

	name := f.Name()

	defer func() {
		_ = os.Remove(name)
	}()

	defer f.Close()

	if _, err := io.Copy(f, bytes.NewReader(data)); err != nil {
		return err
	}

	if err := f.Sync(); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Chmod(name, mode); err != nil {
		return err
	}

	return os.Rename(name, filename)
}
