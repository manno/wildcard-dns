// Package xip provides functions to create a DNS server which, when queried
// with a hostname with an embedded IP address, returns that IP Address.  It
// was inspired by xip.io, which was created by Sam Stephenson
package xip

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// DomainCustomizations are values that are returned for specific queries.
// The map key is the the domain in question, e.g. "sslip.io." (always include trailing dot).
// For example, when querying for MX records for "sslip.io", return the protonmail servers,
// but when querying for MX records for generic queries, e.g. "127.0.0.1.sslip.io", return the
// default (which happens to be no MX records).
//
// Noticeably absent are the NS records and SOA records. They don't need to be customized
// because they are always the same, regardless of the domain being queried.
type DomainCustomization struct {
	A     []dnsmessage.AResource
	AAAA  []dnsmessage.AAAAResource
	CNAME dnsmessage.CNAMEResource
	MX    []dnsmessage.MXResource
	TXT   []dnsmessage.TXTResource
}

type DomainCustomizations map[string]DomainCustomization

// There's nothing like global variables to make my heart pound with joy.
// Some of these are global because they are, in essence, constants which
// I don't want to waste time recreating with every function call.
// But `Customizations` is a true global variable.
var (
	ipv4REDots   = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1\d|[1-9])?\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9])?\d))($|[.-])`)
	ipv4REDashes = regexp.MustCompile(`(^|[.-])(((25[0-5]|(2[0-4]|1\d|[1-9])?\d)-){3}(25[0-5]|(2[0-4]|1\d|[1-9])?\d))($|[.-])`)
	// https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
	ipv6RE           = regexp.MustCompile(`(^|[.-])(([0-9a-fA-F]{1,4}-){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,7}-|([0-9a-fA-F]{1,4}-){1,6}-[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,5}(-[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}-){1,4}(-[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}-){1,3}(-[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}-){1,2}(-[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}-((-[0-9a-fA-F]{1,4}){1,6})|-((-[0-9a-fA-F]{1,4}){1,7}|-)|fe80-(-[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|--(ffff(-0{1,4})?-)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))($|[.-])`)
	dns01ChallengeRE = regexp.MustCompile(`(?i)_acme-challenge\.`)

	// allowPublicIPs controls whether IP addresses in the public internet can be resolved.
	// Set WILD_ALLOW_PUBLIC_IPS=true to enable. Defaults to false to prevent DNS amplification attacks.
	allowPublicIPs = os.Getenv("WILD_ALLOW_PUBLIC_IPS") == "true"

	domain  = os.Getenv("WILD_DOMAIN")
	ns1Name = os.Getenv("WILD_NS1")
	ns2Name = os.Getenv("WILD_NS2")
	ns3Name = os.Getenv("WILD_NS3")
	ns1IP   = os.Getenv("WILD_NS1_IP")

	// Initialized in init() after env var validation.
	mbox           dnsmessage.Name
	NameServers    []dnsmessage.NSResource
	Customizations DomainCustomizations
)

func init() {
	required := map[string]string{
		"WILD_DOMAIN": domain,
		"WILD_NS1":    ns1Name,
		"WILD_NS2":    ns2Name,
		"WILD_NS3":    ns3Name,
		"WILD_NS1_IP": ns1IP,
	}
	for name, val := range required {
		if val == "" {
			log.Fatalf("required environment variable %s is not set; see .envrc.template", name)
		}
	}

	var err error
	var ns1, ns2, ns3 dnsmessage.Name
	if ns1, err = dnsmessage.NewName(ns1Name); err != nil {
		log.Fatalf("WILD_NS1 %q is not a valid DNS name: %v", ns1Name, err)
	}
	if ns2, err = dnsmessage.NewName(ns2Name); err != nil {
		log.Fatalf("WILD_NS2 %q is not a valid DNS name: %v", ns2Name, err)
	}
	if ns3, err = dnsmessage.NewName(ns3Name); err != nil {
		log.Fatalf("WILD_NS3 %q is not a valid DNS name: %v", ns3Name, err)
	}
	if mbox, err = dnsmessage.NewName(fmt.Sprintf("nop.%s", domain)); err != nil {
		log.Fatalf("WILD_DOMAIN %q produced an invalid mailbox name: %v", domain, err)
	}

	ns1IPBytes, err := ipv4ToBytes(ns1IP)
	if err != nil {
		log.Fatalf("WILD_NS1_IP %q is not a valid IPv4 address: %v", ns1IP, err)
	}

	NameServers = []dnsmessage.NSResource{
		{NS: ns1},
		{NS: ns2},
		{NS: ns3},
	}
	Customizations = DomainCustomizations{
		domain: {A: []dnsmessage.AResource{{A: [4]byte{127, 0, 0, 1}}}},
		// nameserver addresses; we get queries for those every once in a while
		ns1Name: {A: []dnsmessage.AResource{{A: ns1IPBytes}}},
		ns2Name: {A: []dnsmessage.AResource{{A: ns1IPBytes}}},
		ns3Name: {A: []dnsmessage.AResource{{A: ns1IPBytes}}},
	}
}

func ipv4ToBytes(ipString string) ([4]byte, error) {
	ip := net.ParseIP(ipString).To4()
	if ip == nil {
		return [4]byte{}, fmt.Errorf("not a valid IPv4 address: %q", ipString)
	}
	return [4]byte{ip[0], ip[1], ip[2], ip[3]}, nil
}

// Response Why do I have a crazy struct of fields of arrays of functions?
// It's because I can't use dnsmessage.Builder as I had hoped; specifically
// I need to set the Header _after_ I process the message, but Builder expects
// it to be set first, so I use the functions as a sort of batch process to
// create the Builder. What in Header needs to be tweaked? Certain TXT records
// need to unset the authoritative field, and queries for ANY record need
// to set the rcode.
type Response struct {
	Header      dnsmessage.Header
	Answers     []func(*dnsmessage.Builder) error
	Authorities []func(*dnsmessage.Builder) error
	Additionals []func(*dnsmessage.Builder) error
}

// QueryResponse takes in a raw (packed) DNS query and returns a raw (packed)
// DNS response, a string (for logging) that describes the query and the
// response, and an error. It takes in the raw data to offload as much as
// possible from main(). main() is hard to unit test, but functions like
// QueryResponse are not as hard.
//
// Examples of log strings returned:
//
//	78.46.204.247.33654: TypeA 127-0-0-1.sslip.io ? 127.0.0.1
//	78.46.204.247.33654: TypeA www.sslip.io ? nil, SOA
//	78.46.204.247.33654: TypeNS www.example.com ? NS
//	78.46.204.247.33654: TypeSOA www.example.com ? SOA
//	2600::.33654: TypeAAAA --1.sslip.io ? ::1
func QueryResponse(queryBytes []byte, sourceAddr net.IP) (responseBytes []byte, logMessage string, err error) {
	var queryHeader dnsmessage.Header
	var p dnsmessage.Parser
	var response = &Response{}

	if queryHeader, err = p.Start(queryBytes); err != nil {
		return nil, "", err
	}
	var q dnsmessage.Question
	// we only answer the first question even though there technically may be more than one;
	// de facto there's one and only one question
	if q, err = p.Question(); err != nil {
		return nil, "", err
	}
	response.Header = ResponseHeader(queryHeader, dnsmessage.RCodeSuccess)
	logMessage, err = processQuestion(q, response, sourceAddr)
	if err != nil {
		return nil, "", err
	}

	b := dnsmessage.NewBuilder(nil, response.Header)
	b.EnableCompression()
	if err = b.StartQuestions(); err != nil {
		return nil, "", err
	}
	if err = b.Question(q); err != nil {
		return
	}
	if err = b.StartAnswers(); err != nil {
		return nil, "", err
	}
	for _, answer := range response.Answers {
		if err = answer(&b); err != nil {
			return nil, "", err
		}
	}
	if err = b.StartAuthorities(); err != nil {
		return nil, "", err
	}
	for _, authority := range response.Authorities {
		if err = authority(&b); err != nil {
			return nil, "", err
		}
	}
	if err = b.StartAdditionals(); err != nil {
		return nil, "", err
	}
	for _, additionals := range response.Additionals {
		if err = additionals(&b); err != nil {
			return nil, "", err
		}
	}
	if responseBytes, err = b.Finish(); err != nil {
		return nil, "", err
	}
	return responseBytes, logMessage, nil
}

func processQuestion(q dnsmessage.Question, response *Response, sourceAddr net.IP) (logMessage string, _ error) {
	var err error
	logMessage = q.Type.String() + " " + q.Name.String() + " ? "
	if IsAcmeChallenge(q.Name.String()) { // thanks @NormanR
		// delegate everything to its stripped (remove "_acme-challenge.") address, e.g.
		// dig _acme-challenge.127-0-0-1.sslip.io mx → NS 127-0-0-1.sslip.io
		response.Header.Authoritative = false // we're delegating, so we're not authoritative
		return NSResponse(q.Name, response, logMessage)
	}
	switch q.Type {
	case dnsmessage.TypeA:
		{
			nameToAs := NameToA(q.Name.String())
			if len(nameToAs) == 0 {
				// No Answers, only 1 Authorities
				soaHeader, soaResource := SOAAuthority(q.Name)
				response.Authorities = append(response.Authorities,
					func(b *dnsmessage.Builder) error {
						if err = b.SOAResource(soaHeader, soaResource); err != nil {
							return err
						}
						return nil
					})
				return logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
			}
			response.Answers = append(response.Answers,
				// 1 or more A records; A records > 1 only available via Customizations
				func(b *dnsmessage.Builder) error {
					for _, nameToA := range nameToAs {
						err = b.AResource(dnsmessage.ResourceHeader{
							Name:   q.Name,
							Type:   dnsmessage.TypeA,
							Class:  dnsmessage.ClassINET,
							TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
							Length: 0,
						}, nameToA)
						if err != nil {
							return err
						}
					}
					return nil
				})
			var logMessages []string
			for _, nameToA := range nameToAs {
				ip := net.IP(nameToA.A[:])
				logMessages = append(logMessages, ip.String())
			}
			return logMessage + strings.Join(logMessages, ", "), nil
		}
	case dnsmessage.TypeAAAA:
		{
			nameToAAAAs := NameToAAAA(q.Name.String())
			if len(nameToAAAAs) == 0 {
				// No Answers, only 1 Authorities
				soaHeader, soaResource := SOAAuthority(q.Name)
				response.Authorities = append(response.Authorities,
					func(b *dnsmessage.Builder) error {
						if err = b.SOAResource(soaHeader, soaResource); err != nil {
							return err
						}
						return nil
					})
				return logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
			}
			response.Answers = append(response.Answers,
				// 1 or more AAAA records; AAAA records > 1 only available via Customizations
				func(b *dnsmessage.Builder) error {
					for _, nameToAAAA := range nameToAAAAs {
						err = b.AAAAResource(dnsmessage.ResourceHeader{
							Name:   q.Name,
							Type:   dnsmessage.TypeAAAA,
							Class:  dnsmessage.ClassINET,
							TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
							Length: 0,
						}, nameToAAAA)
						if err != nil {
							return err
						}
					}
					return nil
				})
			var logMessages []string
			for _, nameToAAAA := range nameToAAAAs {
				ip := net.IP(nameToAAAA.AAAA[:])
				logMessages = append(logMessages, ip.String())
			}
			return logMessage + strings.Join(logMessages, ", "), nil
		}
	case dnsmessage.TypeALL:
		{
			// We don't implement type ANY, so return "NotImplemented" like CloudFlare (1.1.1.1)
			// https://blog.cloudflare.com/rfc8482-saying-goodbye-to-any/
			// Google (8.8.8.8) returns every record they can find (A, AAAA, SOA, NS, MX, ...).
			response.Header.RCode = dnsmessage.RCodeNotImplemented
			return logMessage + "NotImplemented", nil
		}
	case dnsmessage.TypeCNAME:
		{
			// If there is a CNAME, there can only be 1, and only from Customizations
			cname := CNAMEResource(q.Name.String())
			if cname == nil {
				// No Answers, only 1 Authorities
				soaHeader, soaResource := SOAAuthority(q.Name)
				response.Authorities = append(response.Authorities,
					func(b *dnsmessage.Builder) error {
						if err = b.SOAResource(soaHeader, soaResource); err != nil {
							return err
						}
						return nil
					})
				return logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
			}
			response.Answers = append(response.Answers,
				// 1 CNAME record, via Customizations
				func(b *dnsmessage.Builder) error {
					err = b.CNAMEResource(dnsmessage.ResourceHeader{
						Name:   q.Name,
						Type:   dnsmessage.TypeCNAME,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, *cname)
					if err != nil {
						return err
					}
					return nil
				})
			return logMessage + cname.CNAME.String(), nil
		}
	case dnsmessage.TypeMX:
		{
			mailExchangers := MXResources(q.Name.String())
			var logMessages []string

			// We can be sure that len(mailExchangers) > 1, but we check anyway
			if len(mailExchangers) == 0 {
				return "", errors.New("no MX records, but there should be one")
			}
			response.Answers = append(response.Answers,
				// 1 or more A records; A records > 1 only available via Customizations
				func(b *dnsmessage.Builder) error {
					for _, mailExchanger := range mailExchangers {
						err = b.MXResource(dnsmessage.ResourceHeader{
							Name:   q.Name,
							Type:   dnsmessage.TypeMX,
							Class:  dnsmessage.ClassINET,
							TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
							Length: 0,
						}, mailExchanger)
					}
					if err != nil {
						return err
					}
					return nil
				})
			for _, mailExchanger := range mailExchangers {
				logMessages = append(logMessages, strconv.Itoa(int(mailExchanger.Pref))+" "+mailExchanger.MX.String())
			}
			return logMessage + strings.Join(logMessages, ", "), nil
		}
	case dnsmessage.TypeNS:
		{
			return NSResponse(q.Name, response, logMessage)
		}
	case dnsmessage.TypeSOA:
		{
			soaResource := SOAResource(q.Name)
			response.Answers = append(response.Answers,
				func(b *dnsmessage.Builder) error {
					err = b.SOAResource(dnsmessage.ResourceHeader{
						Name:   q.Name,
						Type:   dnsmessage.TypeSOA,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, soaResource)
					if err != nil {
						return err
					}
					return nil
				})
			return logMessage + soaLogMessage(soaResource), nil
		}
	case dnsmessage.TypeTXT:
		{
			// if it's an "_acme-challenge." TXT, we return no answer but an NS authority & not authoritative
			// if it's customized records, we return them in the Answers
			// otherwise we return no Answers and Authorities SOA
			var txts []dnsmessage.TXTResource
			txts = TXTResources(q.Name.String())
			if len(txts) == 0 {
				// If there are no txt resources, return the source IP addr
				txts = []dnsmessage.TXTResource{{TXT: []string{sourceAddr.String()}}}
			}
			response.Answers = append(response.Answers,
				// 1 or more TXT records via Customizations
				// Technically there can be more than one TXT record, but practically there can only be one record
				// but with multiple strings
				func(b *dnsmessage.Builder) error {
					for _, txt := range txts {
						err = b.TXTResource(dnsmessage.ResourceHeader{
							Name:   q.Name,
							Type:   dnsmessage.TypeTXT,
							Class:  dnsmessage.ClassINET,
							TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
							Length: 0,
						}, txt)
						if err != nil {
							return err
						}
					}
					return nil
				})
			var logMessageTXTss []string
			for _, txt := range txts {
				logMessageTXTs := append([]string(nil), txt.TXT...)
				logMessageTXTss = append(logMessageTXTss, `["`+strings.Join(logMessageTXTs, `", "`)+`"]`)
			}
			return logMessage + strings.Join(logMessageTXTss, ", "), nil
		}
	default:
		{
			// default is the same case as an A/AAAA record which is not found,
			// i.e. we return no answers, but we return an authority section
			// No Answers, only 1 Authorities
			soaHeader, soaResource := SOAAuthority(q.Name)
			response.Authorities = append(response.Authorities,
				func(b *dnsmessage.Builder) error {
					if err = b.SOAResource(soaHeader, soaResource); err != nil {
						return err
					}
					return nil
				})
			return logMessage + "nil, SOA " + soaLogMessage(soaResource), nil
		}
	}
}

// NSResponse sets the Answers/Authorities depending whether we're delegating or authoritative
// (whether it's an "_acme-challenge." domain or not). Either way, it supplies the Additionals
// (IP addresses of the nameservers).
func NSResponse(name dnsmessage.Name, response *Response, logMessage string) (string, error) {
	nameServers := NSResources(name.String())
	var logMessages []string
	if response.Header.Authoritative {
		// we're authoritative, so we reply with the answers
		response.Answers = append(response.Answers,
			func(b *dnsmessage.Builder) error {
				for _, nameServer := range nameServers {
					err := b.NSResource(dnsmessage.ResourceHeader{
						Name:   name,
						Type:   dnsmessage.TypeNS,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, nameServer)
					if err != nil {
						return err
					}
				}
				return nil
			})
	} else {
		// we're NOT authoritative, so we reply who is authoritative
		response.Authorities = append(response.Authorities,
			func(b *dnsmessage.Builder) error {
				for _, nameServer := range nameServers {
					err := b.NSResource(dnsmessage.ResourceHeader{
						Name:   name,
						Type:   dnsmessage.TypeNS,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, nameServer)
					if err != nil {
						return err
					}
				}
				return nil
			})
		logMessage += "nil, NS " // we're not supplying an answer; we're supplying the NS record that's authoritative
	}
	response.Additionals = append(response.Additionals,
		func(b *dnsmessage.Builder) error {
			for _, nameServer := range nameServers {
				for _, aResource := range NameToA(nameServer.NS.String()) {
					err := b.AResource(dnsmessage.ResourceHeader{
						Name:   nameServer.NS,
						Type:   dnsmessage.TypeA,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, aResource)
					if err != nil {
						return err
					}
				}
				for _, aaaaResource := range NameToAAAA(nameServer.NS.String()) {
					err := b.AAAAResource(dnsmessage.ResourceHeader{
						Name:   nameServer.NS,
						Type:   dnsmessage.TypeAAAA,
						Class:  dnsmessage.ClassINET,
						TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; long TTL, these IP addrs don't change
						Length: 0,
					}, aaaaResource)
					if err != nil {
						return err
					}
				}
			}
			return nil
		})
	for _, nameServer := range nameServers {
		logMessages = append(logMessages, nameServer.NS.String())
	}
	return logMessage + strings.Join(logMessages, ", "), nil
}

// ResponseHeader returns a pre-fab DNS response header.
// We are almost always authoritative (exception: _acme-challenge TXT records)
// We are not recursing
// servers, so recursion is never available.  We're able to
// "white label" domains by indiscriminately matching every query that comes
// our way. Not being recursive has the added benefit of not being usable as an
// amplifier in a DDOS attack. We pass in the RCODE, which is normally RCodeSuccess
// but can also be a failure (e.g. ANY type we return RCodeNotImplemented)
func ResponseHeader(query dnsmessage.Header, rcode dnsmessage.RCode) dnsmessage.Header {
	return dnsmessage.Header{
		ID:                 query.ID,
		Response:           true,
		OpCode:             0,
		Authoritative:      true,
		Truncated:          false,
		RecursionDesired:   query.RecursionDesired,
		RecursionAvailable: false,
		RCode:              rcode,
	}
}

// NameToA returns an []AResource that matched the hostname
// IsPublic returns true if the IP is routable on the public internet.
// Private, loopback, link-local, and CG-NAT ranges all return false.
func IsPublic(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		// CG-NAT 100.64.0.0/10
		if ip4[0] == 100 && ip4[1]&0xc0 == 64 {
			return false
		}
		return true
	}
	// IPv4/IPv6 Translation 64:ff9b:1::/48
	if ip[0] == 0 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
		ip[4] == 0 && ip[5] == 1 {
		return false
	}
	// Teredo/ORCHIDv2 2001::/32 and 2001:20::/28
	if ip[0] == 0x20 && ip[1] == 1 && ip[2] == 0 && ip[3]&0xf0 == 0x20 {
		return false
	}
	// Documentation 2001:db8::/32
	if ip[0] == 0x20 && ip[1] == 1 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return false
	}
	return true
}

func NameToA(fqdnString string) []dnsmessage.AResource {
	fqdn := []byte(fqdnString)
	// is it a customized A record? If so, return early
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok && len(domain.A) > 0 {
		return domain.A
	}
	for _, ipv4RE := range []*regexp.Regexp{ipv4REDashes, ipv4REDots} {
		if ipv4RE.Match(fqdn) {
			match := string(ipv4RE.FindSubmatch(fqdn)[2])
			match = strings.ReplaceAll(match, "-", ".")
			ipv4address := net.ParseIP(match).To4()
			if ipv4address == nil {
				return []dnsmessage.AResource{}
			}
			if !allowPublicIPs && IsPublic(ipv4address) {
				return []dnsmessage.AResource{}
			}
			return []dnsmessage.AResource{
				{A: [4]byte{ipv4address[0], ipv4address[1], ipv4address[2], ipv4address[3]}},
			}
		}
	}
	return []dnsmessage.AResource{}
}

// NameToAAAA returns an []AAAAResource that matched the hostname
func NameToAAAA(fqdnString string) []dnsmessage.AAAAResource {
	fqdn := []byte(fqdnString)
	// is it a customized AAAA record? If so, return early
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok && len(domain.AAAA) > 0 {
		return domain.AAAA
	}
	if !ipv6RE.Match(fqdn) {
		return []dnsmessage.AAAAResource{}
	}

	ipv6RE.Longest()
	match := string(ipv6RE.FindSubmatch(fqdn)[2])
	match = strings.ReplaceAll(match, "-", ":")
	ipv16address := net.ParseIP(match).To16()
	if ipv16address == nil {
		// We shouldn't reach here because `match` should always be valid, but we're not optimists
		return []dnsmessage.AAAAResource{}
	}
	if !allowPublicIPs && IsPublic(ipv16address) {
		return []dnsmessage.AAAAResource{}
	}

	AAAAR := dnsmessage.AAAAResource{}
	copy(AAAAR.AAAA[:], ipv16address)
	return []dnsmessage.AAAAResource{AAAAR}
}

// CNAMEResource returns the CNAME via Customizations, otherwise nil
func CNAMEResource(fqdnString string) *dnsmessage.CNAMEResource {
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok && domain.CNAME != (dnsmessage.CNAMEResource{}) {
		return &domain.CNAME
	}
	return nil
}

// MXResources returns either 1 or more MX records set via Customizations or
// an MX record pointing to the queried record
func MXResources(fqdnString string) []dnsmessage.MXResource {
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok && len(domain.MX) > 0 {
		return domain.MX
	}
	mx, _ := dnsmessage.NewName(fqdnString)
	return []dnsmessage.MXResource{
		{
			Pref: 0,
			MX:   mx,
		},
	}
}

func IsAcmeChallenge(fqdnString string) bool {
	if dns01ChallengeRE.MatchString(fqdnString) {
		// bypass public IP filter: ACME challenges must work for all IPs
		saved := allowPublicIPs
		allowPublicIPs = true
		ipv4s := NameToA(fqdnString)
		ipv6s := NameToAAAA(fqdnString)
		allowPublicIPs = saved
		if len(ipv4s) > 0 || len(ipv6s) > 0 {
			return true
		}
	}
	return false
}

func NSResources(fqdnString string) []dnsmessage.NSResource {
	if IsAcmeChallenge(fqdnString) {
		strippedFqdn := dns01ChallengeRE.ReplaceAllString(fqdnString, "")
		ns, _ := dnsmessage.NewName(strippedFqdn)
		return []dnsmessage.NSResource{{NS: ns}}
	}
	return NameServers
}

// TXTResources returns TXT records from Customizations
func TXTResources(fqdnString string) []dnsmessage.TXTResource {
	if domain, ok := Customizations[strings.ToLower(fqdnString)]; ok {
		return domain.TXT
	}
	return nil
}

func SOAAuthority(name dnsmessage.Name) (dnsmessage.ResourceHeader, dnsmessage.SOAResource) {
	return dnsmessage.ResourceHeader{
		Name:   name,
		Type:   dnsmessage.TypeSOA,
		Class:  dnsmessage.ClassINET,
		TTL:    604800, // 60 * 60 * 24 * 7 == 1 week; it's not gonna change
		Length: 0,
	}, SOAResource(name)
}

// SOAResource returns the hard-coded (except MNAME) SOA
func SOAResource(name dnsmessage.Name) dnsmessage.SOAResource {
	return dnsmessage.SOAResource{
		NS:     name,
		MBox:   mbox,
		Serial: 2021061900,
		// cribbed the Refresh/Retry/Expire from google.com
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		MinTTL:  300,
	}
}

// soaLogMessage returns an easy-to-read string for logging SOA Answers/Authorities
func soaLogMessage(soaResource dnsmessage.SOAResource) string {
	return soaResource.NS.String() + " " +
		soaResource.MBox.String() + " " +
		strconv.Itoa(int(soaResource.Serial)) + " " +
		strconv.Itoa(int(soaResource.Refresh)) + " " +
		strconv.Itoa(int(soaResource.Retry)) + " " +
		strconv.Itoa(int(soaResource.Expire)) + " " +
		strconv.Itoa(int(soaResource.MinTTL))
}
