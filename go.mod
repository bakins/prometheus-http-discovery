module github.com/bakins/prometheus-http-discovery

go 1.13

require (
	github.com/go-kit/kit v0.10.0
	github.com/gophercloud/gophercloud v0.8.0 // indirect
	github.com/prometheus/client_golang v1.3.0
	github.com/prometheus/common v0.8.0
	github.com/prometheus/prometheus v1.8.2-0.20200213233353-b90be6f32a33
	github.com/stretchr/testify v1.4.0
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v2 v2.2.8
)

replace (
	github.com/golang/lint => golang.org/x/lint v0.0.0-20190409202823-959b441ac422
	k8s.io/klog => github.com/simonpasquier/klog-gokit v0.1.0
)
