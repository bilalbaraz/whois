package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultWhoisServer = "whois.iana.org"
	whoisPort          = "43"
	lookupTimeout      = 10 * time.Second
)

func init() {
	rootCmd.AddCommand(lookupCmd)
}

var lookupCmd = &cobra.Command{
	Use:   "lookup <domain>",
	Short: "Lookup WHOIS data for a domain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, err := normalizeDomain(args[0])
		if err != nil {
			return err
		}

		server, err := findWhoisServer(domain)
		if err != nil {
			return err
		}

		response, err := queryWhois(server, domain)
		if err != nil {
			return err
		}

		fmt.Fprint(cmd.OutOrStdout(), response)
		return nil
	},
}

func normalizeDomain(input string) (string, error) {
	value := strings.TrimSpace(input)
	if value == "" {
		return "", errors.New("domain is required")
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil && parsed.Host != "" {
			value = parsed.Host
		}
	}

	// Strip path if still present (e.g. example.com/path)
	if idx := strings.IndexByte(value, '/'); idx >= 0 {
		value = value[:idx]
	}
	// Strip port if present (e.g. example.com:443)
	if idx := strings.IndexByte(value, ':'); idx >= 0 {
		value = value[:idx]
	}

	value = strings.TrimSuffix(value, ".")
	value = strings.ToLower(value)

	if !strings.Contains(value, ".") {
		return "", fmt.Errorf("invalid domain: %q", input)
	}

	return value, nil
}

func findWhoisServer(domain string) (string, error) {
	// Query IANA for the TLD referral server.
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid domain: %q", domain)
	}

	tld := parts[len(parts)-1]
	ianaResp, err := queryWhois(defaultWhoisServer, tld)
	if err != nil {
		return "", err
	}

	server := parseReferralServer(ianaResp)
	if server == "" {
		// Fallback to IANA when no referral is found.
		server = defaultWhoisServer
	}

	return server, nil
}

func parseReferralServer(response string) string {
	scanner := bufio.NewScanner(strings.NewReader(response))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "refer:") || strings.HasPrefix(lower, "whois:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func queryWhois(server, query string) (string, error) {
	addr := net.JoinHostPort(server, whoisPort)
	conn, err := net.DialTimeout("tcp", addr, lookupTimeout)
	if err != nil {
		return "", fmt.Errorf("connect to %s failed: %w", server, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(lookupTimeout))
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", fmt.Errorf("send query failed: %w", err)
	}

	builder := &strings.Builder{}
	if _, err := io.Copy(builder, conn); err != nil {
		return "", fmt.Errorf("read response failed: %w", err)
	}

	return builder.String(), nil
}
