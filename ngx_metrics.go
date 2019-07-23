// ngx_metrics collects nginx performance metrics via syslog feed from nginx
// and makes them available for prometheus to scrape.
package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/mcuadros/go-syslog.v2"
)

// TODO(badrpc):
//  * flags for syslog and http protocol endpoints
//		web.listen-address
//		syslog.listen-address
//  * syslog
//  * daemonize or let the OS manage this?

var (
	// TODO(badrpc): all of these should probably go into labels of request
	// related metrics:
	//
	// AncientBrowser
	// Host
	// Pipe
	// RemoteUser
	// RequestCompletion
	// Scheme
	// ServerName
	// ServerProtocol
	// Status

	httpBodyBytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_body_bytes_sent_total",
			Help: "Number of bytes sent to a client, not counting the response header.",
		},
		[]string{"code", "host", "scheme"},
	)
	httpBytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_bytes_sent_total",
			Help: "Number of bytes sent to clients.",
		},
		[]string{"code", "host", "scheme"},
	)
	httpBytesRecieved = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_bytes_received_total",
			Help: "Number of bytes received from clients.",
		},
		[]string{"code", "host", "scheme"},
	)
	httpConnectionsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_connections_active",
			Help: "Number of active client connections including waiting connections.",
		},
	)
	httpConnectionsReading = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_connections_reading",
			Help: "Number of connections where nginx is reading the request header",
		},
	)
	httpConnectionsWaiting = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_connections_waiting",
			Help: "Number of connections where nginx is writing the response back to the client.",
		},
	)
	httpConnectionsWriting = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_connections_writing",
			Help: "Number of idle client connections waiting for a request.",
		},
	)
	httpRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Number of HTTP(s) requests served.",
		},
		[]string{"code", "host", "scheme"},
	)
	httpRequestLength = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "http_request_length_bytes",
			Help: "Request length histogram.",
			// TODO(badrpc): make buckets configurable via command line flag.
			Buckets: []float64{32.0, 64.0, 96.0, 128.0, 256.0, 512.0, 1024.0},
		},
	)
	httpRequestDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "http_request_duration_seconds",
			Help: "Request duration historgram.",
			// TODO(badrpc): make buckets configurable via command line flag.
			Buckets: []float64{0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 2.000, 5.000},
		},
	)
)

type logRecord struct {
	AncientBrowser     string
	BodyBytesSent      int
	BytesSent          int
	ConnectionsActive  int
	ConnectionsReading int
	ConnectionsWaiting int
	ConnectionsWriting int
	Host               string
	Pipe               string
	RemoteUser         string
	RequestCompletion  string
	RequestLength      int
	RequestTime        float64
	Scheme             string
	ServerName         string
	ServerProtocol     string
	Status             string
}

func processMessage(s string) {
	var r logRecord
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		log.Printf("json.Unmarshal(%q): %v", s, err)
		return
	}
	requestLables := prometheus.Labels{"code": r.Status, "host": r.Host, "scheme": r.Scheme}
	httpBodyBytesSent.With(requestLables).Add(float64(r.BodyBytesSent))
	httpBytesRecieved.With(requestLables).Add(float64(r.RequestLength))
	httpBytesSent.With(requestLables).Add(float64(r.BytesSent))
	httpConnectionsActive.Set(float64(r.ConnectionsActive))
	httpConnectionsReading.Set(float64(r.ConnectionsReading))
	httpConnectionsWaiting.Set(float64(r.ConnectionsWaiting))
	httpConnectionsWriting.Set(float64(r.ConnectionsWriting))
	httpRequestDuration.Observe(r.RequestTime)
	httpRequestLength.Observe(float64(r.RequestLength))
	httpRequests.With(requestLables).Inc()
}

func main() {
	prometheus.MustRegister(httpBodyBytesSent)
	prometheus.MustRegister(httpBytesRecieved)
	prometheus.MustRegister(httpBytesSent)
	prometheus.MustRegister(httpConnectionsActive)
	prometheus.MustRegister(httpConnectionsReading)
	prometheus.MustRegister(httpConnectionsWaiting)
	prometheus.MustRegister(httpConnectionsWriting)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(httpRequestLength)
	prometheus.MustRegister(httpRequests)

	// flag.Parse()

	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)
	server.ListenUDP("0.0.0.0:9514")

	server.Boot()

	go func(channel syslog.LogPartsChannel) {
		// TODO(badrpc): handle channel closure. End process?
		for logParts := range channel {
			content := logParts["content"]
			s, ok := content.(string)
			if !ok {
				log.Printf("Type assertion .(string) failed for %+v", content)
				continue
			}
			processMessage(s)
		}
	}(channel)

	http.Handle("/metrics", promhttp.Handler())
	log.Print(http.ListenAndServe(":9516", nil))
	// TODO(badrpc): handle exit from http.ListenAndServe(). End process?

	server.Wait()
}
