package managesieveserver

import "github.com/mjl-/mox/sievefilter"

func init() {
	// Default validator. Hosts may replace via SetValidator.
	SetValidator(sievefilter.Validate)
}
