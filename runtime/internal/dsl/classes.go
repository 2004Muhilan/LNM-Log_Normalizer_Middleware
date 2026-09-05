package dsl

import (
	"net"
	"regexp"
)

// Token classes are structural validators (contracts/README.md). A class mismatch on a promoted
// parser is a parse failure: the event is quarantined, never mis-typed.
var classPatterns = map[string]*regexp.Regexp{
	"integer":  regexp.MustCompile(`^-?[0-9]+$`),
	"float":    regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?$`),
	"ipv4":     regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`),
	"ipv6":     regexp.MustCompile(`^[0-9A-Fa-f:.]+$`),
	"ip":       regexp.MustCompile(`^[0-9A-Fa-f:.]+$`),
	"mac":      regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$`),
	"url":      regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*://[^\s]+|[A-Za-z0-9.\-_\[\]:]+(:[0-9]+)?(/[^\s]*)?)$`),
	"hostname": regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`),
	"uuid":     regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`),
	"hex":      regexp.MustCompile(`^(0x)?[0-9a-fA-F]+$`),
	"word":     regexp.MustCompile(`^[A-Za-z0-9_.:\-]+$`),
	"text":     regexp.MustCompile(`^[^\x00]*$`),
}

func classRe(class string) *regexp.Regexp { return classPatterns[class] }

// classOK validates a token against its class; ip classes are additionally parsed.
func classOK(class string, tok []byte) bool {
	re := classPatterns[class]
	if re == nil || !re.Match(tok) {
		return false
	}
	switch class {
	case "ipv4":
		ip := net.ParseIP(string(tok))
		return ip != nil && ip.To4() != nil
	case "ipv6":
		ip := net.ParseIP(string(tok))
		return ip != nil && ip.To4() == nil
	case "ip":
		return net.ParseIP(string(tok)) != nil
	}
	return true
}
