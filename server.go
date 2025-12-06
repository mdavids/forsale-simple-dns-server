package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"net"

	"github.com/miekg/dns"
)

const (
	zoneName   = "dynamic.testdns.nl."
	defaultTTL = 300
	//nameserver = "ns1.dynamic.testdns.nl."
	nameserver = "forsalens1.testdns.nl."
	hostmaster = "noreply.dynamic.testdns.nl."
)

var DefaultNsecTypes = []uint16{
	dns.TypeSOA,
	dns.TypeNS,
	dns.TypeTXT,
	dns.TypeRRSIG,
	dns.TypeNSEC,
	dns.TypeDNSKEY,
}

type Config struct {
	Zone       string   `json:"zone"`
	Ns         []string `json:"ns"`
	Hostmaster string   `json:"hostmaster,omitempty"`
	Ksk        struct {
		Algorithm uint8  `json:"algorithm"`
		PublicKey string `json:"publicKey"`
	} `json:"ksk"`
	Zsk        struct {
		Algorithm uint8  `json:"algorithm"`
		PublicKey string `json:"publicKey"`
	} `json:"zsk"`
	KeySig struct {
		Algorithm  uint8  `json:"algorithm"`
		Expiration uint32 `json:"expiration"`
		Inception  uint32 `json:"inception"`
		KeyTag     uint16 `json:"keyTag"`
		Signature  string `json:"signature"`
	} `json:"keySig"`
	PrivateKey string `json:"privateKey"`
}

type DnssecProvider struct {
	Ksk        *dns.DNSKEY
	Zsk        *dns.DNSKEY
	ZskPrivKey crypto.Signer
	KeySig     *dns.RRSIG
}

type DNSServer struct {
	dnssec     *DnssecProvider
	zone       string
	ns         []string
	hostmaster string
	soa        *dns.SOA
	nsRecords  []*dns.NS
	txtRecords map[string][]*dns.TXT
}

// GenerateDnssecProvider genereert nieuwe DNSSEC keys
func GenerateDnssecProvider(name string, algo uint8, rrTtl, validFrom, validTo uint32) (*DnssecProvider, error) {
	p := &DnssecProvider{
		Ksk: &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    rrTtl,
			},
			Flags:     257, // SEP voor KSK
			Protocol:  3,
			Algorithm: algo,
		},
		Zsk: &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    rrTtl,
			},
			Flags:     256, // Geen SEP voor ZSK
			Protocol:  3,
			Algorithm: algo,
		},
		KeySig: &dns.RRSIG{
			Hdr:        dns.RR_Header{Ttl: rrTtl},
			Algorithm:  algo,
			Expiration: validTo,
			Inception:  validFrom,
			SignerName: name,
		},
	}

	// Genereer keys (256 bits voor ECDSA P256)
	kskPrivateKey, err := p.Ksk.Generate(256)
	if err != nil {
		return nil, err
	}

	zskPrivateKey, err := p.Zsk.Generate(256)
	if err != nil {
		return nil, err
	}

	// Cast naar ECDSA private key
	p.ZskPrivKey = zskPrivateKey.(*ecdsa.PrivateKey)

	// Sign de DNSKEY RRset met KSK
	p.KeySig.KeyTag = p.Ksk.KeyTag()
	err = p.KeySig.Sign(kskPrivateKey.(crypto.Signer), []dns.RR{p.Ksk, p.Zsk})
	if err != nil {
		return nil, err
	}

	return p, nil
}

// PrivKeyBytes extraheert de private key bytes
func (p *DnssecProvider) PrivKeyBytes() ([]byte, error) {
	if p == nil || p.Zsk == nil {
		return nil, fmt.Errorf("zsk must be populated")
	}
	return p.ZskPrivKey.(*ecdsa.PrivateKey).D.Bytes(), nil
}

// SetPrivKeyBytes zet de private key van bytes
func (p *DnssecProvider) SetPrivKeyBytes(b []byte) error {
	if p == nil || p.Zsk == nil {
		return fmt.Errorf("zsk must be populated")
	}

	pubBytes, err := base64.StdEncoding.DecodeString(p.Zsk.PublicKey)
	if err != nil {
		return fmt.Errorf("cannot decode zsk public key: %w", err)
	}

	if len(pubBytes) != 64 {
		return fmt.Errorf("wrong zsk public key length: %v", len(pubBytes))
	}

	p.ZskPrivKey = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(pubBytes[:32]),
			Y:     new(big.Int).SetBytes(pubBytes[32:]),
		},
		D: new(big.Int).SetBytes(b),
	}

	return nil
}

// Sign ondertekent een RRset
func (p *DnssecProvider) Sign(rrs []dns.RR, validFrom, validTo uint32) ([]dns.RR, error) {
	if p == nil || p.Zsk == nil {
		return nil, fmt.Errorf("zsk must be populated")
	}
	if len(rrs) == 0 {
		return nil, nil
	}

	var now uint32
	if validFrom == 0 || validTo == 0 {
		now = uint32(time.Now().Unix())
		if validFrom == 0 {
			validFrom = now - 3600
		}
	}

	// Groepeer per type
	rrsByType := make(map[uint16][]dns.RR)
	for _, rr := range rrs {
		rrtype := rr.Header().Rrtype
		if rrtype != dns.TypeRRSIG {
			rrsByType[rrtype] = append(rrsByType[rrtype], rr)
		}
	}

	var sigs []dns.RR
	for _, rrsOfType := range rrsByType {
		expiration := validTo
		if expiration == 0 {
			expiration = now + 3600 + rrsOfType[0].Header().Ttl
		}

		sig := &dns.RRSIG{
			Hdr:        dns.RR_Header{Ttl: rrsOfType[0].Header().Ttl},
			Algorithm:  p.Zsk.Algorithm,
			Expiration: expiration,
			Inception:  validFrom,
			KeyTag:     p.Zsk.KeyTag(),
			SignerName: p.Zsk.Hdr.Name,
		}

		err := sig.Sign(p.ZskPrivKey, rrsOfType)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, sig)
	}

	return sigs, nil
}

// ToLowerAscii - ascii-only string lowercase (zoals addr.tools)
func ToLowerAscii(s string) string {
	return strings.ToLower(s)
}

// EqualsAsciiIgnoreCase - ascii-only case-insensitive vergelijking
func EqualsAsciiIgnoreCase(s, t string) bool {
	return strings.EqualFold(s, t)
}

// LoadConfig laadt configuratie uit JSON bestand
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// SaveConfig slaat configuratie op naar JSON bestand
func SaveConfig(path string, config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// GenerateConfig genereert een nieuwe configuratie met DNSSEC keys
func GenerateConfig(zone string, ns []string, hostmaster string) (*Config, error) {
	zone = dns.CanonicalName(zone)
	for i := range ns {
		ns[i] = dns.CanonicalName(ns[i])
	}
	if hostmaster != "" {
		hostmaster = dns.CanonicalName(hostmaster)
	}

	now := uint32(time.Now().Unix())
	validFrom := now - now%86400
	validTo := validFrom + 315360000 // 10 jaar

	dnssec, err := GenerateDnssecProvider(zone, dns.ECDSAP256SHA256, defaultTTL, validFrom, validTo)
	if err != nil {
		return nil, err
	}

	privKeyBytes, err := dnssec.PrivKeyBytes()
	if err != nil {
		return nil, err
	}

	config := &Config{
		Zone:       zone,
		Ns:         ns,
		Hostmaster: hostmaster,
		PrivateKey: base64.StdEncoding.EncodeToString(privKeyBytes),
	}

	config.Ksk.Algorithm = dnssec.Ksk.Algorithm
	config.Ksk.PublicKey = dnssec.Ksk.PublicKey
	config.Zsk.Algorithm = dnssec.Zsk.Algorithm
	config.Zsk.PublicKey = dnssec.Zsk.PublicKey
	config.KeySig.Algorithm = dnssec.KeySig.Algorithm
	config.KeySig.Expiration = dnssec.KeySig.Expiration
	config.KeySig.Inception = dnssec.KeySig.Inception
	config.KeySig.KeyTag = dnssec.KeySig.KeyTag
	config.KeySig.Signature = dnssec.KeySig.Signature

	return config, nil
}

// LoadDnssecFromConfig laadt DNSSEC provider uit configuratie
func LoadDnssecFromConfig(config *Config) (*DnssecProvider, error) {
	zone := dns.CanonicalName(config.Zone)

	p := &DnssecProvider{
		Ksk: &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   zone,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Flags:     257,
			Protocol:  3,
			Algorithm: config.Ksk.Algorithm,
			PublicKey: config.Ksk.PublicKey,
		},
		Zsk: &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   zone,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Flags:     256,
			Protocol:  3,
			Algorithm: config.Zsk.Algorithm,
			PublicKey: config.Zsk.PublicKey,
		},
		KeySig: &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   zone,
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			TypeCovered: dns.TypeDNSKEY,
			Algorithm:   config.KeySig.Algorithm,
			Labels:      uint8(dns.CountLabel(zone)),
			OrigTtl:     defaultTTL,
			Expiration:  config.KeySig.Expiration,
			Inception:   config.KeySig.Inception,
			KeyTag:      config.KeySig.KeyTag,
			SignerName:  zone,
			Signature:   config.KeySig.Signature,
		},
	}

	// Laad private key
	privKeyBytes, err := base64.StdEncoding.DecodeString(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot decode private key: %w", err)
	}

	err = p.SetPrivKeyBytes(privKeyBytes)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// NewDNSServer maakt een nieuwe DNS server uit configuratie
func NewDNSServer(config *Config) (*DNSServer, error) {
	dnssec, err := LoadDnssecFromConfig(config)
	if err != nil {
		return nil, err
	}

	zone := dns.CanonicalName(config.Zone)
	hostmaster := config.Hostmaster
	if hostmaster == "" {
		hostmaster = "hostmaster." + zone
	} else {
		hostmaster = dns.CanonicalName(hostmaster)
	}

	server := &DNSServer{
		dnssec:     dnssec,
		zone:       zone,
		ns:         config.Ns,
		hostmaster: hostmaster,
		txtRecords: make(map[string][]*dns.TXT),
	}

	server.setupRecords()
	return server, nil
}

// setupRecords configureert de hardcoded DNS records
func (s *DNSServer) setupRecords() {
	now := uint32(time.Now().Unix())

	// SOA record
	s.soa = &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   s.zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    defaultTTL,
		},
		Ns:      s.ns[0],
		Mbox:    s.hostmaster,
		Serial:  now,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  defaultTTL,
	}

	// NS records
	for _, ns := range s.ns {
		s.nsRecords = append(s.nsRecords, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   s.zone,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Ns: ns,
		})
	}

	// TXT records voor _for-sale subdomain
	// (timestamp en prijs worden dynamisch gegenereerd bij elke query)
	forSaleName := "_for-sale." + s.zone
	s.txtRecords[forSaleName] = []*dns.TXT{
		{
			Hdr: dns.RR_Header{
				Name:   forSaleName,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    1, // Korte TTL voor hele RRset (dynamische data)
			},
			Txt: []string{"v=FORSALE1;ftxt=Let's make up a nice price for this test domain - it is not really for sale!"},
		},
		{
			Hdr: dns.RR_Header{
				Name:   forSaleName,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			Txt: []string{"v=FORSALE1;furi=mailto:email@example.com"},
		},
		{
			Hdr: dns.RR_Header{
				Name:   forSaleName,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			Txt: []string{""}, // Placeholder, wordt per query gevuld met timestamp
		},
		{
			Hdr: dns.RR_Header{
				Name:   forSaleName,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			Txt: []string{""}, // Placeholder, wordt per query gevuld met prijs
		},
	}
}

// addNsecProof voegt NSEC records toe voor denial of existence (zoals addr.tools)
func (s *DNSServer) addNsecProof(req *dns.Msg, resp *dns.Msg, qname string, qtype uint16) error {
	opt := req.IsEdns0()
	if opt == nil || !opt.Do() {
		return nil // Geen DNSSEC gevraagd
	}

	// Bepaal welke types aanwezig zijn
	var types []uint16
	isApex := EqualsAsciiIgnoreCase(qname, s.zone)

	if len(resp.Answer) == 0 {
		if resp.Rcode == dns.RcodeNameError {
			// NXDOMAIN - bewijs dat naam niet bestaat
			types = []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME}
			// RFC9824, dus ook hier NODATA - TODO checken of dit zo goed is danwel beter kan!
			resp.SetRcode(req, dns.RcodeSuccess)
		} else {
			// NODATA - bewijs dat type niet bestaat voor deze naam
			types = make([]uint16, len(DefaultNsecTypes))
			copy(types, DefaultNsecTypes)

			// Verwijder het gevraagde type en types die niet op deze locatie horen
			filteredTypes := []uint16{}
			for _, t := range types {
				if t == qtype {
					continue // Gevraagde type niet in bitmap (want bestaat niet)
				}
				if !isApex && (t == dns.TypeNS || t == dns.TypeSOA || t == dns.TypeDNSKEY) {
					continue // Deze types alleen op apex
				}
				filteredTypes = append(filteredTypes, t)
			}
			types = filteredTypes
		}

		// Maak NSEC record
		nsec := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			NextDomain: "\\000." + ToLowerAscii(qname), // White lie: wijst naar zichzelf
			TypeBitMap: types,
		}
		resp.Ns = append(resp.Ns, nsec)

		// Sign NSEC
		sigs, err := s.dnssec.Sign([]dns.RR{nsec}, 0, 0)
		if err != nil {
			return err
		}
		resp.Ns = append(resp.Ns, sigs...)
	}

	return nil
}

// handleDNS verwerkt inkomende DNS queries
func (s *DNSServer) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = false

	// Get the source IP
	srcIp, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	
// Zit al ergens of zo ?? TODO: testen: dig +dnssec +opcode=1
//	// Alleen queries
//        if req.Opcode != dns.OpcodeQuery {
//                w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeNotImplemented))
//                return
//        }

	// Check EDNS0
	dnssecOK := false
	compactOK :=false
	if opt := req.IsEdns0(); opt != nil {
		dnssecOK = opt.Do()
		compactOK = opt.Co() // RFC9824 (+co flag in dig) - doen we niks mee, alleen loggen
		resp.SetEdns0(1232, dnssecOK)
	}

	if len(req.Question) == 0 {
		resp.SetRcode(req, dns.RcodeFormatError)
		w.WriteMsg(resp)
		return
	}

	q := req.Question[0]
	qname := dns.CanonicalName(q.Name)

	log.Printf("From: %s - Query: %s %s %s (DO: %v, CO: %v)", srcIp, qname, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype], dnssecOK, compactOK)

	// Alleen CLASS IN
	if q.Qclass != dns.ClassINET {
		resp.SetRcode(req, dns.RcodeNotImplemented)
		w.WriteMsg(resp)
		return
	}

	// Geen RRSIG en NSEC query
	// Alleen queries in s.zone
	// Cloudflare accepteert NSEC wel, zie j78.nl
	if q.Qtype == dns.TypeRRSIG || q.Qtype == dns.TypeNSEC || !dns.IsSubDomain(s.zone, qname) {
		resp.SetRcode(req, dns.RcodeRefused)
		w.WriteMsg(resp)
		return
	}

	// Geen ANY 
	if q.Qtype == dns.TypeANY {
		resp.SetRcode(req, dns.RcodeNotImplemented)
		w.WriteMsg(resp)
		return
	}

	// DNSKEY query?
	if q.Qtype == dns.TypeDNSKEY && qname == s.zone {
		resp.Answer = append(resp.Answer, dns.Copy(s.dnssec.Ksk), dns.Copy(s.dnssec.Zsk))
		if dnssecOK {
			resp.Answer = append(resp.Answer, dns.Copy(s.dnssec.KeySig))
		}
		w.WriteMsg(resp)
		return
	}

	// Apex records (zone zelf)
	if qname == s.zone {
		resp.Rcode = dns.RcodeSuccess
		switch q.Qtype {
		case dns.TypeSOA:
			resp.Answer = append(resp.Answer, dns.Copy(s.soa))
			if dnssecOK {
				sigs, err := s.dnssec.Sign(resp.Answer, 0, 0)
				if err == nil {
					resp.Answer = append(resp.Answer, sigs...)
				} else {
					log.Printf("Error signing SOA: %v", err)
				}
			}
		case dns.TypeNS:
			for _, ns := range s.nsRecords {
				resp.Answer = append(resp.Answer, dns.Copy(ns))
			}
			if dnssecOK {
				sigs, err := s.dnssec.Sign(resp.Answer, 0, 0)
				if err == nil {
					resp.Answer = append(resp.Answer, sigs...)
				} else {
					log.Printf("Error signing NS: %v", err)
				}
			}
		default:
			// NODATA - geen data voor dit type op apex
			resp.Ns = append(resp.Ns, dns.Copy(s.soa))
			if dnssecOK {
				sigs, err := s.dnssec.Sign(resp.Ns, 0, 0)
				if err == nil {
					resp.Ns = append(resp.Ns, sigs...)
				} else {
					log.Printf("Error signing authority SOA: %v", err)
				}
			}
			// Voeg NSEC proof toe
			if err := s.addNsecProof(req, resp, qname, q.Qtype); err != nil {
				log.Printf("Error adding NSEC proof: %v", err)
			}
		}
		w.WriteMsg(resp)
		return
	}

	// TXT records?
	if txtRecs, exists := s.txtRecords[qname]; exists {
		if q.Qtype == dns.TypeTXT {
			resp.Rcode = dns.RcodeSuccess

			// Prijs stappen voor random selectie
			priceSteps := []int{100, 250, 500, 750, 1000, 1500, 2000, 2500, 3000, 4000, 5000,
				7500, 10000, 15000, 20000, 25000, 30000, 40000, 50000, 75000, 100000}

			for i, txt := range txtRecs {
				txtCopy := dns.Copy(txt).(*dns.TXT)
				txtCopy.Hdr.Name = qname

				// Voor _for-sale: vul dynamische velden
				if qname == "_for-sale."+s.zone && len(txtCopy.Txt) > 0 && txtCopy.Txt[0] == "" {
					if i == 2 { // Timestamp record
						txtCopy.Txt = []string{fmt.Sprintf("v=FORSALE1;ftxt=%s", time.Now().Format(time.RFC3339))}
					} else if i == 3 { // Prijs record
						price := priceSteps[time.Now().UnixNano()%int64(len(priceSteps))]
						txtCopy.Txt = []string{fmt.Sprintf("v=FORSALE1;fval=EUR%d", price)}
					}
				}
				resp.Answer = append(resp.Answer, txtCopy)
			}
			if dnssecOK && len(resp.Answer) > 0 {
				sigs, err := s.dnssec.Sign(resp.Answer, 0, 0)
				if err == nil {
					resp.Answer = append(resp.Answer, sigs...)
				} else {
					log.Printf("Error signing TXT: %v", err)
				}
			}
			w.WriteMsg(resp)
			return
		} else {
			// Naam bestaat, maar niet het gevraagde type (NODATA)
			resp.Rcode = dns.RcodeSuccess
			resp.Ns = append(resp.Ns, dns.Copy(s.soa))
			if dnssecOK {
				sigs, err := s.dnssec.Sign(resp.Ns, 0, 0)
				if err == nil {
					resp.Ns = append(resp.Ns, sigs...)
				} else {
					log.Printf("Error signing authority SOA: %v", err)
				}
			}
			// Voeg NSEC proof toe
			if err := s.addNsecProof(req, resp, qname, q.Qtype); err != nil {
				log.Printf("Error adding NSEC proof: %v", err)
			}
			w.WriteMsg(resp)
			return
		}
	}

	// Naam bestaat niet (NXDOMAIN)
	resp.SetRcode(req, dns.RcodeNameError)
	resp.Ns = append(resp.Ns, dns.Copy(s.soa))
	if dnssecOK {
		sigs, err := s.dnssec.Sign(resp.Ns, 0, 0)
		if err == nil {
			resp.Ns = append(resp.Ns, sigs...)
		} else {
			log.Printf("Error signing authority SOA: %v", err)
		}
	}
	// Voeg NSEC proof toe voor NXDOMAIN
	if err := s.addNsecProof(req, resp, qname, q.Qtype); err != nil {
		log.Printf("Error adding NSEC proof: %v", err)
	}
	w.WriteMsg(resp)
}

func main() {
	var port int
	var configPath string
	var genConfig bool

	flag.IntVar(&port, "port", 53, "DNS server port")
	flag.StringVar(&configPath, "config", "config.json", "Path to config file")
	flag.BoolVar(&genConfig, "genconfig", false, "Generate new config and exit")
	flag.Parse()

	// Config generation mode?
	if genConfig {
		config, err := GenerateConfig(zoneName, []string{nameserver}, hostmaster)
		if err != nil {
			log.Fatal(err)
		}

		err = SaveConfig(configPath, config)
		if err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}

		// Print DS record
		dnssec, _ := LoadDnssecFromConfig(config)
		ds := dnssec.Ksk.ToDS(dns.SHA256)
		fmt.Printf("Generated config saved to: %s\n\n", configPath)
		fmt.Printf("=== DS Record (add to parent zone) ===\n%s\n", ds.String())
		return
	}

	// Laad of genereer config
	config, err := LoadConfig(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config not found, generating new config: %s", configPath)
			config, err = GenerateConfig(zoneName, []string{nameserver}, hostmaster)
			if err != nil {
				log.Fatal(err)
			}
			err = SaveConfig(configPath, config)
			if err != nil {
				log.Fatalf("Failed to save config: %v", err)
			}
			log.Printf("Config saved to: %s", configPath)
		} else {
			log.Fatalf("Failed to load config: %v", err)
		}
	}

	// Maak DNS server
	server, err := NewDNSServer(config)
	if err != nil {
		log.Fatalf("Failed to create DNS server: %v", err)
	}

	// Print DNSSEC info
	ds := server.dnssec.Ksk.ToDS(dns.SHA256)

	log.Printf("\n=== DNSSEC Keys ===")
	log.Printf("Zone: %s", server.zone)
	log.Printf("DS Record (voor parent zone):\n%s", ds.String())
	log.Printf("===================\n")

	// Registreer handler
	dns.HandleFunc(".", server.handleDNS)

	// Server configuratie
	addr := fmt.Sprintf(":%d", port)

	udpServer := &dns.Server{
		Addr: addr,
		Net:  "udp",
	}

	tcpServer := &dns.Server{
		Addr: addr,
		Net:  "tcp",
	}

	// Start servers
	go func() {
		log.Printf("Starting UDP DNS server on %s", addr)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP server: %v", err)
		}
	}()

	go func() {
		log.Printf("Starting TCP DNS server on %s", addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start TCP server: %v", err)
		}
	}()

	// Wacht op shutdown signaal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	udpServer.Shutdown()
	tcpServer.Shutdown()
}
