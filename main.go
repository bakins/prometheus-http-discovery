package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	prom_config "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/prometheus/discovery/refresh"
	"github.com/prometheus/prometheus/discovery/targetgroup"
	"github.com/prometheus/prometheus/documentation/examples/custom-sd/adapter"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

var (
	discoverTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prometheus_sd_http_calls_total",
			Help: "The total number of HTTP discover calls.",
		},
		[]string{"url", "status"},
	)
)

func init() {
	prometheus.MustRegister(discoverTotal)
}

func main() {
	var (
		config          = kingpin.Flag("config", "discovery configuration file name.").Default("discover.yaml").String()
		listenAddress   = kingpin.Flag("web.listen-address", "The address on which to expose the web interface and generated Prometheus metrics.").Default(":12852").String()
		metricsEndpoint = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
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

	go d.run(ctx)

	go serveHTTP(ctx, *listenAddress, *metricsEndpoint, logger)

	<-signals

	cancel()
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
		rt, err := prom_config.NewRoundTripperFromConfig(c.HTTPClientConfig, "http_sd", false)
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

func (d *Discovery) run(ctx context.Context) {
	var wg sync.WaitGroup

	for _, t := range d.targets {
		t := t

		wg.Add(1)

		r := refresh.NewDiscovery(
			t.logger,
			"http_sd",
			time.Duration(t.config.RefreshInterval),
			t.refresh,
		)

		go func() {
			defer wg.Done()

			a := adapter.NewAdapter(ctx, t.config.File, t.url, r, t.logger)
			a.Run()
		}()
	}

	wg.Wait()
}

func (t *target) recordMetrics(err error) {
	status := "ok"

	if err != nil {
		status = "error"
		_ = level.Error(t.logger).Log("discovery failed", "error", err)
	}

	discoverTotal.WithLabelValues(t.url, status).Add(1)
}

// based on https://prometheus.io/docs/prometheus/latest/configuration/configuration/#file_sd_config
type targetGroup struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels,omitempty"`
}

func (t *target) refresh(ctx context.Context) ([]*targetgroup.Group, error) {
	groups, err := t.discover(ctx)

	t.recordMetrics(err)

	return groups, err
}

func (t *target) discover(ctx context.Context) ([]*targetgroup.Group, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(t.config.Timeout))
	defer cancel()

	req := t.request.WithContext(ctx)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get url %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body %w", err)
	}

	raw := []targetGroup{}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse response body %w", err)
	}

	var out []*targetgroup.Group

	for i, r := range raw {
		tg := targetgroup.Group{
			Source:  strconv.Itoa(i),
			Targets: make([]model.LabelSet, 0, len(r.Targets)),
			Labels:  make(model.LabelSet),
		}

		for _, addr := range r.Targets {
			target := model.LabelSet{model.AddressLabel: model.LabelValue(addr)}
			tg.Targets = append(tg.Targets, target)
		}

		for name, value := range r.Labels {
			label := model.LabelSet{model.LabelName(name): model.LabelValue(value)}
			tg.Labels = tg.Labels.Merge(label)
		}

		out = append(out, &tg)
	}

	return out, nil
}

func serveHTTP(ctx context.Context, listenAddress, metricsEndpoint string, logger log.Logger) {
	http.Handle(metricsEndpoint, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
			<head><title>StatsD Exporter</title></head>
			<body>
			<h1>StatsD Exporter</h1>
			<p><a href="` + metricsEndpoint + `">Metrics</a></p>
			</body>
			</html>`))
	})

	svr := http.Server{
		Addr: listenAddress,
	}

	go func() {
		<-ctx.Done()

		ctx, cancel := context.WithTimeout(ctx, time.Second*10)
		defer cancel()

		_ = svr.Shutdown(ctx)
	}()

	if err := svr.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		_ = level.Error(logger).Log("server failed", "error", err)
	}
}
