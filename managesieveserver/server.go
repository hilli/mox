// Package managesieveserver implements the ManageSieve protocol (RFC 5804).
//
// It serves on TCP port 4190 by default, advertises capabilities including
// STARTTLS and SASL mechanisms, authenticates users against the same store
// as IMAP/SMTP (store.OpenEmailAuth/OpenEmail), and provides script management
// (PUTSCRIPT/LISTSCRIPTS/GETSCRIPT/DELETESCRIPT/RENAMESCRIPT/SETACTIVE/
// HAVESPACE/CHECKSCRIPT/NOOP/LOGOUT/CAPABILITY/AUTHENTICATE).
//
// Scripts are stored per-account in the store.SieveScript / SieveSettings
// tables. Validation of script content is delegated to the sievefilter package
// (which embeds github.com/hilli/sieve-go). Until sievefilter wires sieve-go,
// the validator accepts any non-empty input.
package managesieveserver

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"os"
	"slices"
	"sync"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mlog"
	mox "github.com/mjl-/mox/mox-"
)

// ScriptValidator validates a Sieve script (parse, capabilities). Wired by
// callers (typically sievefilter). If nil, scripts are accepted as-is.
type ScriptValidator func(script []byte) (warnings string, err error)

// validator is the package-level validator. Use SetValidator to replace.
var validator ScriptValidator
var validatorMu sync.RWMutex

// SetValidator wires a script validator. Pass nil to disable validation.
func SetValidator(v ScriptValidator) {
	validatorMu.Lock()
	defer validatorMu.Unlock()
	validator = v
}

func getValidator() ScriptValidator {
	validatorMu.RLock()
	defer validatorMu.RUnlock()
	return validator
}

// SieveExtensions returns the space-separated list of Sieve extensions to
// advertise in the SIEVE capability. By default, the list reflects what
// sievefilter and the upstream sieve-go library support, including the
// Mox-supplied `environment` extension and the `imapsieve` capability used
// by RFC 6785 IMAP-event scripts. Callers (sievefilter) can override it.
var SieveExtensions = "fileinto envelope imap4flags variables subaddress relational body regex mime reject editheader vacation environment imapsieve"

// servers holds closures registered by listen1, each starting accept loops.
var servers []func()

// Listen initializes listeners per the configuration. Call Serve afterward.
func Listen() {
	names := slices.Sorted(maps.Keys(mox.Conf.Static.Listeners))
	for _, name := range names {
		listener := mox.Conf.Static.Listeners[name]

		if !listener.ManageSieve.Enabled {
			continue
		}
		var tlsConfig *tls.Config
		var noTLSClientAuth bool
		if listener.TLS != nil {
			tlsConfig = listener.TLS.Config
			noTLSClientAuth = listener.TLS.ClientAuthDisabled
		}
		port := config.Port(listener.ManageSieve.Port, 4190)
		for _, ip := range listener.IPs {
			listen1(name, ip, port, tlsConfig, noTLSClientAuth, listener.ManageSieve.NoRequireSTARTTLS)
		}
	}
}

func listen1(listenerName, ip string, port int, tlsConfig *tls.Config, noTLSClientAuth, noRequireSTARTTLS bool) {
	log := mlog.New("managesieveserver", nil)
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	if os.Getuid() == 0 {
		log.Print("listening for managesieve",
			slog.String("listener", listenerName),
			slog.String("addr", addr))
	}
	network := mox.Network(ip)
	ln, err := mox.Listen(network, addr)
	if err != nil {
		log.Fatalx("managesieve: listen", err, slog.String("listener", listenerName))
	}

	if tlsConfig != nil {
		tlsConfig = tlsConfig.Clone()
		mox.StartTLSSessionTicketKeyRefresher(mox.Shutdown, log, tlsConfig)
	}

	serve := func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Infox("managesieve: accept", err, slog.String("listener", listenerName))
				continue
			}
			metricConnection.Inc()
			go serveConn(listenerName, mox.Cid(), tlsConfig, conn, noTLSClientAuth, noRequireSTARTTLS)
		}
	}

	servers = append(servers, serve)
}

// Serve starts the accept loops for all listeners registered by Listen.
func Serve() {
	for _, s := range servers {
		go s()
	}
	servers = nil
}
