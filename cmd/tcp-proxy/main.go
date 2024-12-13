package main

import (
	"bytes"
	hx "encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	proxy "github.com/sanderzegers/go-tcp-proxy"
)

var (
	version = "0.0.0-src"
	matchid = uint64(0)
	connid  = uint64(0)
	logger  proxy.ColorLogger

	localAddr   = flag.String("l", ":9999", "local address")
	remoteAddr  = flag.String("r", "localhost:80", "remote address")
	verbose     = flag.Bool("v", false, "display server actions")
	veryverbose = flag.Bool("vv", false, "display server actions and all tcp data")
	nagles      = flag.Bool("n", false, "disable nagles algorithm")
	hex         = flag.Bool("h", false, "output hex")
	colors      = flag.Bool("c", false, "output ansi colors")
	unwrapTLS   = flag.Bool("unwrap-tls", false, "remote connection with TLS exposed unencrypted locally")
	match       = flag.String("match", "", "match regex (in the form 'regex')")
	replace     = flag.String("replace", "", "replace regex (in the form 'regex~replacer')")
	binReplace  = flag.String("binreplace", "", "replace binary (in the form '20a4f3~20a500)")
)

func main() {
	flag.Parse()

	logger := proxy.ColorLogger{
		Verbose: *verbose,
		Color:   *colors,
	}

	logger.Info("go-tcp-proxy (%s) proxing from %v to %v ", version, *localAddr, *remoteAddr)

	laddr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		logger.Warn("Failed to resolve local address: %s", err)
		os.Exit(1)
	}
	raddr, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		logger.Warn("Failed to resolve remote address: %s", err)
		os.Exit(1)
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		logger.Warn("Failed to open local port to listen: %s", err)
		os.Exit(1)
	}

	matcher := createMatcher(*match)
	replacer := createReplacer(*replace)
	binReplacer := createBinReplacer(*binReplace)

	if *veryverbose {
		*verbose = true
	}

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			logger.Warn("Failed to accept connection '%s'", err)
			continue
		}
		connid++

		var p *proxy.Proxy
		if *unwrapTLS {
			logger.Info("Unwrapping TLS")
			p = proxy.NewTLSUnwrapped(conn, laddr, raddr, *remoteAddr)
		} else {
			p = proxy.New(conn, laddr, raddr)
		}

		p.Matcher = matcher
		switch {
		case *replace != "":
			p.Replacer = replacer
		case *binReplace != "":
			p.Replacer = binReplacer
		}

		p.Nagles = *nagles
		p.OutputHex = *hex
		p.Log = proxy.ColorLogger{
			Verbose:     *verbose,
			VeryVerbose: *veryverbose,
			Prefix:      fmt.Sprintf("Connection #%03d ", connid),
			Color:       *colors,
		}

		go p.Start()
	}
}

func createMatcher(match string) func([]byte) {
	if match == "" {
		return nil
	}
	re, err := regexp.Compile(match)
	if err != nil {
		logger.Warn("Invalid match regex: %s", err)
		return nil
	}

	logger.Info("Matching %s", re.String())
	return func(input []byte) {
		ms := re.FindAll(input, -1)
		for _, m := range ms {
			matchid++
			logger.Info("Match #%d: %s", matchid, string(m))
		}
	}
}

func createReplacer(replace string) func([]byte) []byte {
	if replace == "" {
		return nil
	}
	//split by / (TODO: allow slash escapes)
	parts := strings.Split(replace, "~")
	if len(parts) != 2 {
		logger.Warn("Invalid replace option")
		return nil
	}

	re, err := regexp.Compile(string(parts[0]))
	if err != nil {
		logger.Warn("Invalid replace regex: %s", err)
		return nil
	}

	repl := []byte(parts[1])

	logger.Info("Replacing %s with %s", re.String(), repl)
	return func(input []byte) []byte {
		return re.ReplaceAll(input, repl)
	}
}

func createBinReplacer(replace string) func([]byte) []byte {
	if replace == "" {
		return nil
	}

	stringParts := strings.Split(replace, "~")
	if len(stringParts) != 2 {
		logger.Warn("Invalid replace option")
		return nil
	}

	part := make([][]byte, 2)
	var err error

	part[0], err = hx.DecodeString(stringParts[0])

	if err != nil {
		logger.Warn("Invalid createBinReplacer 1st argument", err)
		return nil
	}

	part[1], err = hx.DecodeString(stringParts[1])

	if err != nil {
		logger.Warn("Invalid createBinReplacer 2nd argument", err)
		return nil
	}

	logger.Info("Binary Replacing %s with %s", stringParts[0], stringParts[1])
	return func(input []byte) []byte {
		var result []byte
		start := 0
		for {
			// Find the next occurrence of the search pattern
			index := bytes.Index(input[start:], part[0])
			if index == -1 {
				break
			}

			// Append the part before the match and the replacement
			result = append(result, input[start:start+index]...)
			result = append(result, part[1]...)

			// Move the start position past the matched segment
			start += index + len(part[0])
		}

		// Append the remaining part of the array
		result = append(result, input[start:]...)
		return result
	}
}
