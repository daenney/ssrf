package ssrf

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"

	"golang.org/x/exp/slices"
)

var (
	// ErrProhibitedNetwork is returned when trying to dial a destination whose
	// network type is not in our allow list
	ErrProhibitedNetwork = errors.New("prohibited network type")
	// ErrProhibitedPort is returned when trying to dial a destination on a port
	// number that's not in our allow list
	ErrProhibitedPort = errors.New("prohibited port number")
	// ErrProhibitedIP is returned when trying to dial a destionation whose IP
	// is on our deny list
	ErrProhibitedIP = errors.New("prohibited IP address")
	// ErrInvalidHostPort is returned when [netip.ParseAddrPort] is unable to
	// parse our destination into its host and port constituents
	ErrInvalidHostPort = errors.New("invalid host:port pair")
)

// Option sets an option on a Guardian
type Option = func(g *Guardian)

// WithAllowedV4Prefixes allows explicitly whitelisting (additiona) IPv4
// prefixes. If a prefix is passed here that overlaps with [IPv4SpecialPurpose]
// the request will be permitted.
//
// This function overrides the allowed IPv4 prefixes, it does not accumulate.
func WithAllowedV4Prefixes(prefixes ...netip.Prefix) Option {
	return func(g *Guardian) {
		g.allowedv4Prefixes = prefixes
	}
}

// WithAllowedV6Prefixes allows explicitly whitelisting (additiona) IPv6
// prefixes. If a prefix is passed here that overlaps with [IPv6SpecialPurpose]
// the request will be permitted.
//
// This function overrides the allowed IPv6 prefixes, it does not accumulate.
func WithAllowedV6Prefixes(prefixes ...netip.Prefix) Option {
	return func(g *Guardian) {
		g.allowedv6Prefixes = prefixes
	}
}

// WithDeniedV4Prefixes allows denying IPv4 prefixes in case you want to deny
// more than just [IPv4SpecialPurpose].
//
// This function overrides the denied IPv4 prefixes, it does not accumulate.
//
// The prefixes passed in are prepended to [IPv4SpecialPurpose]. If you want
// to allow calls to a prefix in [IPv4SpecialPurpose], use [WithAllowedV4Prefixes]
// instead.
func WithDeniedV4Prefixes(prefixes ...netip.Prefix) Option {
	return func(g *Guardian) {
		g.deniedv4Prefixes = prefixes
	}
}

// WithDeniedV6Prefixes allows denying IPv6 prefixes in case you want to deny
// more than just [IPv6SpecialPurpose].
//
// This function overrides the denied IPv6 prefixes, it does not accumulate.
//
// The prefixes passed in are prepended to [IPv6SpecialPurpose]. If you want
// to allow calls to a prefix in [IPv6SpecialPurpose], use [WithAllowedV6Prefixes]
// instead.
func WithDeniedV6Prefixes(prefixes ...netip.Prefix) Option {
	return func(g *Guardian) {
		g.deniedv6Prefixes = prefixes
	}
}

// WithPorts allows overriding which destination ports are considered valid. By
// default only requests to 80 and 443 are permitted.
//
// This function overrides the allowed ports, it does not accumulate.
func WithPorts(ports ...uint16) Option {
	return func(g *Guardian) {
		g.ports = ports
	}
}

// WithAnyPort allows requests to any port number. It is equivalent to calling
// [WithPorts] without any arguments.
func WithAnyPort() Option {
	return func(g *Guardian) {
		g.ports = nil
	}
}

// WithNetworks allows overriding which network types/protocols are considered
// valid. By default only tcp4 and tcp6 are permitted.
//
// This function overrides the allowed networks, it does not accumulate.
func WithNetworks(networks ...string) Option {
	return func(g *Guardian) {
		g.networks = networks
	}
}

// WithAnyNetwork allows requests to any network. It is equivalent to calling
// [WithNetworks] without any arguments.
func WithAnyNetwork() Option {
	return func(g *Guardian) {
		g.networks = nil
	}
}

// Guardian will help ensure your network service isn't able to connect to
// certain network/protocols, ports or IP addresses. Once a Guardian has been
// created it is safe for concurrent use, but must not be modified.
//
// The Guardian returned by [New] should be set as the [net.Dialer.Control]
// function.
type Guardian struct {
	networks []string
	ports    []uint16

	allowedv4Prefixes []netip.Prefix
	allowedv6Prefixes []netip.Prefix
	deniedv4Prefixes  []netip.Prefix
	deniedv6Prefixes  []netip.Prefix
}

// New returns a Guardian initialised and ready to keep you safe
//
// It is initialised with 2 defaults:
//   - tcp4 and tcp6 are considered the only valid networks/protocols
//   - 80 and 443 are considered the only valid ports
//
// Both can be overridden by calling [WithNetworks] and [WithPorts] to
// specify different ones, or [WithAnyNetwork] and [WithAnyPort] to
// disable checking for those entirely.
//
// A Guardian always checks if the IP encountered is in the IPv4 or IPv6
// special prefixes [IPv4SpecialPurpose] or [IPv6SpecialPurpose]. If you
// want to allow a call to one of those prefixes you can explicitly permit
// it with [WithAllowedV4Prefixes] or [WithAllowedV6Prefixes]. You can
// also add additional explicitly denied prefixes through
// [WithDeniedV4Prefixes] and [WithDeniedV6Prefixes].
//
// [Guardian.Safe] details the order in which things are checked.
func New(opts ...Option) *Guardian {
	g := &Guardian{
		networks: []string{"tcp4", "tcp6"},
		ports:    []uint16{80, 443},
	}

	for _, opt := range opts {
		opt(g)
	}

	g.deniedv4Prefixes = append(g.deniedv4Prefixes, IPv4SpecialPurpose...)
	g.deniedv6Prefixes = append(g.deniedv6Prefixes, IPv6SpecialPurpose...)

	return g
}

// Safe is the function that should be passed in the [net.Dialer]'s Control field
//
// This function checks a number of things, in sequence:
//   - Does the network string match the permitted protocols? If not, deny the request,
//     otherwise move on to the next check
//   - Does the port match one of our permitted ports? If not, deny the quest, otherwise
//     move on to the next check
//
// Then, for either IPv4 or IPv6:
//   - Is the IP within an explicitly allowed IPvX prefix? If so, allow it, otherwise
//     move on to the next check
//   - Is the IP within an explicitly denied IPvX prefix? If so, deny it, otherwise
//     move on to the next check
//   - Is the IP within the IPvXSpecialPrefix? If so, deny it
//
// If nothing matched, the request is permitted.
func (g *Guardian) Safe(network string, address string, _ syscall.RawConn) error {
	if g.networks != nil {
		if !slices.Contains(g.networks, network) {
			return fmt.Errorf("%s is not a permitted network type: %w", network, ErrProhibitedNetwork)
		}
	}

	ipport, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("could not parse: %s: %s: %w", address, err, ErrInvalidHostPort)
	}

	if g.ports != nil {
		port := ipport.Port()
		if !slices.Contains(g.ports, port) {
			return fmt.Errorf("%d is not a permitted port: %w", port, ErrProhibitedPort)
		}
	}

	ip := ipport.Addr()

	if ip.Is6() {
		for _, net := range g.allowedv6Prefixes {
			if net.Contains(ip) {
				return nil
			}
		}
		for _, net := range g.deniedv6Prefixes {
			if net.Contains(ip) {
				return fmt.Errorf("%s is not a permitted destination: %w", ip, ErrProhibitedIP)
			}
		}
		return nil
	}

	// Since it's not IPv6, it's IPv4. Is6 catches IPv4-mapped IPv6 addresses
	for _, net := range g.allowedv4Prefixes {
		if net.Contains(ip) {
			return nil
		}
	}
	for _, net := range g.deniedv4Prefixes {
		if net.Contains(ip) {
			return fmt.Errorf("%s is not a permitted destination: %w", ip, ErrProhibitedIP)
		}
	}

	return nil
}
