package managesieveserver

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricConnection = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "mox_managesieve_connection_total",
			Help: "Number of incoming ManageSieve connections.",
		},
	)
	metricCommands = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_managesieve_command_duration_seconds",
			Help:    "ManageSieve command duration and result.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 30},
		},
		[]string{"cmd", "result"},
	)
)
