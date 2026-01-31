package cmd

import (
	"bufio"
	"encoding/json"
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

var (
	lookupRaw    bool
	lookupJSON   bool
	lookupServer string
)

func init() {
	rootCmd.AddCommand(lookupCmd)
	lookupCmd.Flags().BoolVar(&lookupRaw, "raw", false, "Print raw WHOIS response only")
	lookupCmd.Flags().BoolVar(&lookupJSON, "json", false, "Print response as JSON")
	lookupCmd.Flags().StringVar(&lookupServer, "server", "", "Manual WHOIS server (host only)")
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

		if lookupRaw && lookupJSON {
			return errors.New("cannot use --raw and --json together")
		}

		server := lookupServer
		if server == "" {
			server, err = findWhoisServer(domain)
			if err != nil {
				return err
			}
		}

		response, err := queryWhois(server, domain)
		if err != nil {
			return err
		}

		if lookupRaw {
			fmt.Fprint(cmd.OutOrStdout(), response)
			return nil
		}

		if lookupJSON {
			parsed := parseWhoisResponse(response)
			if len(parsed) == 0 {
				parsed = map[string][]string{
					"raw": {response},
				}
			}
			out := lookupJSONOutput{
				Domain: domain,
				Server: server,
				Fields: parsed,
			}
			return writeJSON(cmd, out)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Server: %s\n\n%s", server, response)
		return nil
	},
}

type lookupJSONOutput struct {
	Domain string              `json:"domain"`
	Server string              `json:"server"`
	Fields map[string][]string `json:"fields"`
}

func writeJSON(cmd *cobra.Command, value any) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func parseWhoisResponse(response string) map[string][]string {
	fields := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(response))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			continue
		}
		fields[key] = append(fields[key], value)
	}
	return fields
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
