package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
)

const (
	ipv4SpecialPurposeRegistry = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv"
	ipv6SpecialPurposeRegistry = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv"
)

var (
	additionalV4Entries = []entry{
		{Name: "Multicast", Prefix: "224.0.0.0/4", RFC: "RFC 5771"},
	}
	additionalV6Entries = []entry{
		{Name: "Multicast", Prefix: "ff00::/8", RFC: "RFC 4291"},
	}
)

func main() {
	output := flag.String("output.gen", "", "file to write the generated code into")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := loadTemplates(); err != nil {
		errExit(err, 1)
	}

	v4, err := fetch(ctx, ipv4SpecialPurposeRegistry)
	if err != nil {
		errExit(err, 1)
	}
	v6, err := fetch(ctx, ipv6SpecialPurposeRegistry)
	if err != nil {
		errExit(err, 1)
	}

	f, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		errExit(err, 1, f)
	}
	defer f.Close()

	if t, ok := templates["ssrf.tmpl"]; ok {
		data := struct {
			V4 []entry
			V6 []entry
		}{
			V4: append(v4, additionalV4Entries...),
			V6: append(v6, additionalV6Entries...),
		}
		if err := t.Execute(f, data); err != nil {
			errExit(err, 1, f)
		}
		if res, err := exec.Command("go", "fmt", *output).CombinedOutput(); err != nil {
			fmt.Println(string(res))
		}
	}
}

// cleanRFC tries to clean up the RFC field from the IANA Special Purpose
// registry CSV and turn it into something consistent
func cleanRFC(s string) string {
	s = strings.ReplaceAll(s, "\n", ",")
	s = strings.ReplaceAll(s, "][", ", ")
	s = strings.ReplaceAll(s, "[", "")
	s = strings.ReplaceAll(s, "]", "")
	s = strings.ReplaceAll(s, "RFC", "RFC ")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// cleanName does some small transformations on the Name of a prefix
func cleanName(s string) string {
	return strings.ReplaceAll(s, "Translat.", "Translation")
}

// errExit prints the error, attempts to close any passed in files and then
// exits with the provided code
func errExit(err error, code int, files ...*os.File) {
	fmt.Println(err)
	for _, f := range files {
		_ = f.Close()
	}
	os.Exit(code)
}

// handleNetwork is used to deal with the fact that a Prefix from the IANA
// Special Purpose registry can contain more than one prefix
func handleNetwork(s string) []string {
	list := strings.Split(s, ",")
	res := []string{}

	for _, l := range list {
		l := strings.TrimSpace(l)
		i := strings.Index(l, " ")
		if i == -1 {
			res = append(res, l)
		} else {
			res = append(res, l[:i])
		}
	}
	return res
}

// entry represent a single prefix from a IANA Special Purpose registry
type entry struct {
	Prefix string
	Name   string
	RFC    string
}

// fetch retrieves a particular IANA Special Purpose registry and parses the
// returned CSV into [Entry]s.
//
// This function deduplicates prefixes and calls a number of cleaner functions
// on the data.
func fetch(ctx context.Context, url string) ([]entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "ssrfgen (+https://code.dny.dev/ssrf")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request for %s: %w", url, err)
	}

	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	r := csv.NewReader(resp.Body)
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to parse record in %s: %w", url, err)
	}

	entries := []entry{}
	for _, rec := range records[1:] {
		rec := rec
		prefixes := rec[0]
		for _, p := range handleNetwork(prefixes) {
			p := p
			if !containsPrefix(entries, p) {
				entries = append(entries, entry{
					Prefix: p,
					Name:   cleanName(rec[1]),
					RFC:    cleanRFC(rec[2]),
				})
			}
		}
	}
	return entries, nil
}

// containsPrefix checks if a prefix we're encountering is already matched by
// a previous entry.
//
// The IANA registries are sorted by prefix, so a larger prefix will show up
// before a smaller one. This means we can simply iterate over the list.
func containsPrefix(entries []entry, prefix string) bool {
	p2 := netip.MustParsePrefix(prefix)

	found := false
	for _, e := range entries {
		e := e
		p1 := netip.MustParsePrefix(e.Prefix)
		if p2.Bits() >= p1.Bits() {
			pp, err := p2.Addr().Prefix(p1.Bits())
			if err != nil {
				return false // This should never happen unless we're mix-matching v4 and v6
			}
			found = pp.Addr() == p1.Addr()
			if found {
				fmt.Printf("Skipping prefix: %s matched by entry: %s (%s)\n", prefix, e.Prefix, e.Name)
				break
			}
		}
	}
	return found
}
