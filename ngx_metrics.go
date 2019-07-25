// Copyright 2019 Oleg Sharoyko
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ngx_metrics collects nginx performance metrics via syslog feed from nginx
// and makes them available for prometheus to scrape.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/mcuadros/go-syslog.v2"
)

// TODO(badrpc): allow arbitrary labels directly from syslog message.

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

func parseAddr(addrSpec string) (family, addr string) {
	addr = addrSpec
	if i := strings.Index(addrSpec, "|"); i > 0 {
		family = addrSpec[:i]
		addr = addrSpec[i+1:]
	}
	return family, addr
}

func main() {
	var syslogListenAddr, webListenAddr, webTelemetryPath string

	flag.StringVar(&syslogListenAddr, "syslog.listen-address", "127.0.0.1:9999", "Address to listen on for syslog packets.")
	flag.StringVar(&webListenAddr, "web.listen-address", ":9998", "Address to listen on for HTTP requests.")
	flag.StringVar(&webTelemetryPath, "web.telemetry-path", "/metrics", "Path to expose metrics.")

	flag.Parse()

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

	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)
	var err error
	switch f, a := parseAddr(syslogListenAddr); f {
	case "tcp":
		err = server.ListenTCP(a)
	case "unix", "unixgram", "unixpacket":
		err = server.ListenUnixgram(a)
	case "udp":
		err = server.ListenUDP(a)
	default:
		err = server.ListenUDP(syslogListenAddr)
	}
	if err != nil {
		log.Fatal("Cannot listen for syslog packets on ", syslogListenAddr, ": ", err)
	}

	if err := server.Boot(); err != nil {
		log.Fatal("Cannot start syslog server: ", err)
	}

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

	http.Handle(webTelemetryPath, promhttp.Handler())
	log.Print(http.ListenAndServe(webListenAddr, nil))
	// TODO(badrpc): handle exit from http.ListenAndServe(). End process?

	server.Wait()
}
