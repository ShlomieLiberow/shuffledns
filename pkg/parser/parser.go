package parser

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
)

type OnResultFN func(domain string, ip []string) error

type DNSRecord struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Class    string  `json:"class"`
	Status   string  `json:"status"`
	Data     DNSData `json:"data"`
	Resolver string  `json:"resolver"`
}

// DNSData represents the "data" field in the DNS record.
type DNSData struct {
	Answers []struct {
		TTL  int    `json:"ttl"`
		Type string `json:"type"`
		Name string `json:"name"`
		Data string `json:"data"`
	} `json:"answers,omitempty"`
	Authorities []struct {
		TTL  int    `json:"ttl"`
		Type string `json:"type"`
		Name string `json:"name"`
		Data string `json:"data"`
	} `json:"authorities,omitempty"`
}

// ParseOption is an option for parsing the massdns output.
type ParseOption bool

const (
	ParseStandard ParseOption = false
	ParseNDJSON   ParseOption = true
)

func ParseFile(filename string, callback OnResultFN, option ParseOption) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return Parse(file, callback, option)
}

func Parse(reader io.Reader, callback OnResultFN, ndjson ParseOption) error {
	if ndjson {
		return parseNDJSON(reader, callback)
	}
	return parseRaw(reader, callback)
}

// parseRaw parses the massdns output returning the found
// domain and ip pair to a onResult function.
func parseRaw(reader io.Reader, onResult OnResultFN) error {
	var (
		// Some boolean various needed for state management
		answerStart bool
		cnameStart  bool
		nsStart     bool

		// Result variables to store the results
		domain string
		ip     []string
	)

	// Parse the input line by line and act on what the line means
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}

		// Ignore fields with less than 4 characters
		if len(text) < 4 {
			continue
		}

		// Empty line represents a separator between DNS reply
		// due to `-o Snl` option set in massdns. Thus it can be
		// interpreted as a DNS answer header.
		//
		// If we have start of a DNS answer header, set the
		// bool state to default, and return the results to the
		// consumer via the callback.
		if text[0] == ';' && text[1] == ';' && text[2] == ' ' && text[3] == 'A' && text[4] == 'N' {
			if domain != "" {
				cnameStart, nsStart = false, false
				if err := onResult(domain, ip); err != nil {
					return err
				}
				domain, ip = "", nil
			}
			answerStart = true
			continue
		}

		if answerStart {
			// Non empty line represents DNS answer section, we split on space,
			// iterate over all the parts, and write the answer to the struct.
			parts := strings.Split(text, " ")

			if len(parts) != 5 {
				continue
			}

			// Switch on the record type, deciding what to do with
			// a record based on the type of record.
			switch parts[3] {
			case "NS":
				// If we have a NS record, then set nsStart
				// which will ignore all the next records
				nsStart = true
			case "CNAME":
				// If we have a CNAME record, then the next record should be
				// the values for the CNAME record, so set the cnameStart value.
				//
				// Use the domain in the first cname field since the next fields for
				// A record may contain domain for secondary CNAME which messes
				// up recursive CNAME records.
				if !cnameStart {
					nsStart = false
					domain = strings.TrimSuffix(parts[0], ".")
					cnameStart = true
				}
			case "A":
				// If we have an A record, check if it's not after
				// an NS record. If not, append it to the ips.
				//
				// Also if we aren't inside a CNAME block, set the domain too.
				if !nsStart {
					if !cnameStart && domain == "" {
						domain = strings.TrimSuffix(parts[0], ".")
					}
					ip = append(ip, parts[4])
				}
			}
		}
	}

	// Return error if there was any.
	if err := scanner.Err(); err != nil {
		return err
	}

	// Final callback to deliver the last piece of result
	// if there's any.
	if domain != "" {
		if err := onResult(domain, ip); err != nil {
			return err
		}
	}
	return nil
}

func parseNDJSON(reader io.Reader, onResult OnResultFN) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		var record DNSRecord
		text := scanner.Text()

		// Unmarshal the JSON line into the DNSRecord struct
		if err := json.Unmarshal([]byte(text), &record); err != nil {
			return err // Handle or log error as appropriate
		}

		// Initialize variables to store the results
		var domain string
		var ips []string

		// Check if the record type is A and status is NOERROR
		if record.Type == "A" && record.Status == "NOERROR" {
			domain = strings.TrimSuffix(record.Name, ".")
			for _, answer := range record.Data.Answers {
				if answer.Type == "A" {
					ips = append(ips, answer.Data)
				}
			}
			// If we have IPs, call the callback with the domain and IPs
			if len(ips) > 0 {
				if err := onResult(domain, ips); err != nil {
					return err
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
