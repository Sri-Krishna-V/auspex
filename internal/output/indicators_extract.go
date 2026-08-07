package output

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file extracts observed agent activity into the indicator types a
// SOC or threat-intel analyst actually enriches: domains/FQDNs, IPv4/IPv6
// addresses, URLs, file hashes, and email addresses. It does the typing,
// canonicalization, and noise filtering; the accumulator in indicators.go folds
// the results into deduplicated records.

// Indicator types. These are the value shapes that map onto external threat
// feeds and enrichment services, named so a consumer can route by type without
// re-inspecting the value.
const (
	IndicatorDomain = "domain"
	IndicatorIPv4   = "ipv4"
	IndicatorIPv6   = "ipv6"
	IndicatorURL    = "url"
	IndicatorEmail  = "email"
	IndicatorMD5    = "md5"
	IndicatorSHA1   = "sha1"
	IndicatorSHA256 = "sha256"
)

// typedIndicator is one classified, canonicalized indicator value ready to be folded.
type typedIndicator struct{ typ, val string }

const maxExtractedIndicatorsPerField = 256

// urlInText matches an http(s) URL run inside arbitrary text (a command line, a
// content excerpt). The scheme match is case-insensitive ((?i) on the http(s)://
// prefix only) so an uppercase/mixed-case scheme (HTTPS://, Http://) is recognized
// as a URL and routed through canonicalization + blankURLs like a lowercase one;
// otherwise its userinfo (e.g. HTTPS://8.8.8.8@evil.example/x) would escape the
// URL miner and get re-leaked by the standalone ipv4/hash/email miners. The (?i)
// scopes only the scheme so the rest of the run keeps its original case (paths and
// hosts are case-folded later by canonicalizeURL, not by the matcher). It stops at
// whitespace or shell/quote metacharacters so a URL embedded in a `curl ... | head`
// pipeline is captured without trailing pipe/redirect noise.
var urlInText = regexp.MustCompile(`(?i:https?)://[^\s"'<>` + "`" + `|;)\\]+`)

// uriSchemeInText starts generic URI authority scanning. A small walker below
// finds the actual host boundary because userinfo may contain URI punctuation
// that also separates adjacent prose.
var uriSchemeInText = regexp.MustCompile(`(?i:[a-z][a-z0-9+.-]*)://`)

// emailInText matches a conservative email address shape. The local part and
// domain are restricted to the characters that appear in real addresses; the TLD
// must be at least two letters so a bare `a@b` or a version string is not caught.
var emailInText = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// hashInText matches a MAXIMAL hex run of 32+ chars; classifyHash then accepts it
// only at an exact 32/40/64 length (md5/sha1/sha256). Matching the maximal run
// (rather than an alternation, which RE2 resolves leftmost-first and would clip a
// 64-char digest to its first 32) means a too-long run is matched whole and
// rejected by length, never sliced. It matches ONLY the token; hashBoundary
// validates the edges WITHOUT consuming them, so two adjacent hashes separated by
// a single space/comma are both captured. hashBoundary rejects a run abutting a
// hex digit, '-', or ':' (a UUID segment or colon fingerprint, not a file hash).
var hashInText = regexp.MustCompile(`[0-9A-Fa-f]{32,}`)

// ipv4InText matches a dotted-quad run. Like hashInText it matches only the token
// and leaves boundary validation to ipv4Boundary, so adjacent addresses
// ("8.8.8.8 9.9.9.9") are both captured. net.ParseIP in classifyHost rejects
// out-of-range octets.
var ipv4InText = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)

// extractIndicators returns every indicator carried by s, classified and canonicalized.
// s is one observed-artifact field (a URL, a command line, a content excerpt).
// It mines, in order: http(s) URLs (each also contributing its host as a
// domain/ipv4/ipv6), dotted-quad IPv4 addresses, file hashes, and emails. Noise
// (loopback/private IPs, *.local) is dropped here so it never reaches the dedup
// map.
//
// Domains are deliberately taken ONLY from URL hosts and email domains, never
// mined from bare free text: a bare dotted token in prose ("models.rs",
// "config.json", "v1.2.0") is indistinguishable from a hostname without a TLD
// allowlist, and emitting those as domains is exactly the noise this rewrite
// removes. A real C2/exfil host an analyst cares about is virtually always
// observed as a URL or an email domain, so this keeps precision high without
// losing the indicators that matter.
func extractIndicators(s string, markdown bool) ([]typedIndicator, bool) {
	if s == "" {
		return nil, false
	}
	s = refang(s)
	var out []typedIndicator
	seen := make(map[typedIndicator]struct{})
	truncated := false
	add := func(typ, val string) {
		if typ == "" || val == "" {
			return
		}
		k := typedIndicator{typ, val}
		if _, ok := seen[k]; ok {
			return
		}
		if len(val) > maxIndicatorValueBytes || len(seen) >= maxExtractedIndicatorsPerField {
			truncated = true
			return
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}

	urlMatches := urlInText.FindAllStringIndex(s, maxExtractedIndicatorsPerField+1)
	if len(urlMatches) > maxExtractedIndicatorsPerField {
		truncated = true
	}
	for _, loc := range urlMatches {
		raw := trimTrailingMarkdownEmphasis(s, loc[0], loc[1], markdown)
		if len(raw) > maxIndicatorValueBytes {
			truncated = true
			continue
		}
		canon, host := canonicalizeURL(raw)
		if canon == "" {
			continue
		}
		htyp, hval := classifyHost(host)
		// A URL whose host is noise is itself noise: drop the URL and the host
		// together.
		if htyp == "" {
			continue
		}
		add(IndicatorURL, canon)
		add(htyp, hval)
	}

	uriMatches := uriAuthorities(s, maxExtractedIndicatorsPerField+1)
	if len(uriMatches) > maxExtractedIndicatorsPerField {
		truncated = true
	}
	for _, loc := range uriMatches {
		if loc.host == "" {
			continue
		}
		if typ, val := classifyHost(loc.host); typ != "" {
			add(typ, val)
		}
	}

	// All non-URL miners run over a URL-blanked view of the text: bytes inside a
	// URL authority (notably userinfo, user:pass@host) have already been decided
	// by URL canonicalization and must never be reclassified as a standalone indicator.
	// Otherwise `https://8.8.8.8@evil.example/x` leaks a bogus ipv4 from the
	// userinfo and `https://<32hex>@evil.example/y` leaks a bogus hash from the
	// password — both mis-type and republish a credential. Blanking (not deleting)
	// preserves offsets so nothing outside a URL shifts.
	blanked := blankURLs(s)
	ipMatches := ipv4InText.FindAllStringIndex(blanked, maxExtractedIndicatorsPerField+1)
	if len(ipMatches) > maxExtractedIndicatorsPerField {
		truncated = true
	}
	for _, loc := range ipMatches {
		if !ipv4Boundary(blanked, loc[0], loc[1]) {
			continue
		}
		if typ, val := classifyHost(blanked[loc[0]:loc[1]]); typ != "" {
			add(typ, val)
		}
	}
	hashMatches := hashInText.FindAllStringIndex(blanked, maxExtractedIndicatorsPerField+1)
	if len(hashMatches) > maxExtractedIndicatorsPerField {
		truncated = true
	}
	for _, loc := range hashMatches {
		if !hashBoundary(blanked, loc[0], loc[1]) {
			continue
		}
		if typ, val := classifyHash(blanked[loc[0]:loc[1]]); typ != "" {
			add(typ, val)
		}
	}
	emailMatches := emailInText.FindAllString(blanked, maxExtractedIndicatorsPerField+1)
	if len(emailMatches) > maxExtractedIndicatorsPerField {
		truncated = true
	}
	for _, e := range emailMatches {
		if typ, val := classifyEmail(e); typ != "" {
			add(typ, val)
		}
	}
	return out, truncated
}

type uriAuthority struct {
	start int
	end   int
	host  string
}

func uriAuthorities(s string, limit int) []uriAuthority {
	schemes := uriSchemeInText.FindAllStringIndex(s, limit)
	out := make([]uriAuthority, 0, len(schemes))
	for _, loc := range schemes {
		end := loc[1]
		for end < len(s) && !uriHardTerminator(s[end]) {
			end++
		}
		host, authorityEnd, ok := uriHost(s[loc[1]:end])
		if !ok {
			continue
		}
		scheme := s[loc[0] : loc[1]-3]
		if strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https") {
			host = ""
		}
		out = append(out, uriAuthority{start: loc[0], end: loc[1] + authorityEnd, host: host})
	}
	return out
}

func uriHost(authority string) (string, int, bool) {
	if sep := strings.IndexAny(authority, ",;&"); sep >= 0 {
		if host, ok := parsedURIHost(authority[:sep]); ok {
			return host, sep, true
		}
	}
	for search := 0; search < len(authority); {
		rel := strings.IndexByte(authority[search:], '@')
		if rel < 0 {
			break
		}
		at := search + rel
		end := at + 1
		for end < len(authority) && !uriHostSeparator(authority[end]) {
			end++
		}
		if host, ok := parsedURIHost(authority[at+1 : end]); ok {
			return host, end, true
		}
		search = at + 1
	}
	end := 0
	for end < len(authority) && !uriHostSeparator(authority[end]) {
		end++
	}
	host, ok := parsedURIHost(authority[:end])
	return host, end, ok
}

func uriHostSeparator(b byte) bool {
	switch b {
	case ',', ';', '&', '\'', '(', ')', '*', '+', '=':
		return true
	}
	return false
}

func uriHardTerminator(b byte) bool {
	switch b {
	case '/', '?', '#', '"', '`', '<', '>', '\\', '{', '}', '|', '^':
		return true
	}
	return b <= ' ' || b >= 0x7f
}

func parsedURIHost(hostport string) (string, bool) {
	if hostport == "" || strings.ContainsRune(hostport, '@') {
		return "", false
	}
	u, err := url.Parse("scheme://" + hostport)
	if err != nil || u.User != nil || u.Host != hostport || u.Hostname() == "" {
		return "", false
	}
	return u.Hostname(), true
}

// trimTrailingMarkdownEmphasis removes an exact closing bold marker from a
// Markdown-capable field only when a valid opening marker precedes the URL.
func trimTrailingMarkdownEmphasis(s string, start, end int, markdown bool) string {
	raw := s[start:end]
	if !markdown || !strings.HasSuffix(raw, "**") || strings.HasSuffix(raw, "***") {
		return raw
	}

	prefix := s[:start]
	if strings.Contains(prefix, "`") {
		return raw
	}
	if line := strings.LastIndexByte(prefix, '\n'); line >= 0 {
		prefix = prefix[line+1:]
	}
	open := strings.LastIndex(prefix, "**")
	if open < 0 || (open > 0 && (prefix[open-1] == '*' || prefix[open-1] == '\\')) {
		return raw
	}
	after := open + 2
	if after >= len(prefix) || prefix[after] == '*' {
		return raw
	}
	r, _ := utf8.DecodeRuneInString(prefix[after:])
	if !unicode.IsLetter(r) && !unicode.IsNumber(r) {
		return raw
	}
	return strings.TrimSuffix(raw, "**")
}

// canonicalizeURL parses raw and returns a canonical URL string plus its
// bracketless host. Canonicalization lowercases the scheme and host, removes a
// DNS root dot, drops a default port, strips a trailing fragment (the part after
// '#' carries no indicator signal and inflates dedup), and STRIPS USERINFO. The caller
// redacts the field before extraction, so credential-like query values have
// already been masked. An unparseable URL yields "", "".
//
// Userinfo (user:pass@) is dropped unconditionally: a URL password is a live
// credential with no enrichment value, so it must never reach the emitted url
// indicator. This is a structural guarantee, not pattern-matching — a generic
// password redact.String cannot recognize would otherwise survive into the value.
//
// An IPv6 literal host is re-bracketed when reassembling the authority so the
// emitted url stays parseable (https://[2001:db8::1]:8443/x, not the ambiguous
// https://2001:db8::1:8443/x). The returned host is bracketless so classifyHost
// can type it as a clean ipv6 indicator.
func canonicalizeURL(raw string) (canon, host string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Fragment = ""
	u.User = nil
	host = trimHostRootDot(strings.ToLower(u.Hostname()))
	if host == "" {
		return "", ""
	}
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	authHost := host
	if strings.Contains(host, ":") { // IPv6 literal: restore mandatory brackets.
		authHost = "[" + host + "]"
	}
	if port != "" {
		u.Host = authHost + ":" + port
	} else {
		u.Host = authHost
	}
	return u.String(), host
}

// classifyHost classifies a bare host (from a URL authority or a standalone
// token) as an ipv4, ipv6, or domain indicator, returning "" to DROP it as
// non-actionable noise: a loopback or private/link-local IP, an unspecified
// address, or a *.local / *.localhost name.
func classifyHost(host string) (typ, val string) {
	host = strings.ToLower(strings.TrimSpace(host))
	host = trimHostRootDot(host)
	if host == "" {
		return "", ""
	}
	if ip := net.ParseIP(host); ip != nil {
		if isNoiseIP(ip) {
			return "", ""
		}
		if ip.To4() != nil {
			return IndicatorIPv4, ip.String()
		}
		return IndicatorIPv6, ip.String()
	}
	if !looksLikeDomain(host) {
		return "", ""
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") {
		return "", ""
	}
	return IndicatorDomain, host
}

// looksLikeDomain reports whether host is a plausible FQDN: at least two
// dot-separated labels, each a valid DNS label, with an alphabetic or punycode
// TLD. The TLD rule keeps a dotted token that is really a version string
// ("1.2.3") from being typed as a domain while still accepting IDN hosts encoded
// as punycode.
func looksLikeDomain(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
			if !ok {
				return false
			}
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
	}
	tld := labels[len(labels)-1]
	return looksLikeTLD(tld)
}

func looksLikeTLD(tld string) bool {
	if len(tld) < 2 {
		return false
	}
	if strings.HasPrefix(tld, "xn--") && len(tld) > len("xn--") {
		return true
	}
	for i := 0; i < len(tld); i++ {
		if tld[i] < 'a' || tld[i] > 'z' {
			return false
		}
	}
	return true
}

// isNoiseIP reports whether ip is non-actionable as an external indicator:
// loopback, RFC1918 / unique-local private space, link-local, the unspecified
// address, or multicast. These never identify external infrastructure, so they
// are dropped rather than enriched.
func isNoiseIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

// classifyHash types a hex run by length: 32 -> md5, 40 -> sha1, 64 -> sha256.
// The value is lowercased so the same digest written in either case dedupes to
// one indicator. The regex guarantees the length, so default is unreachable.
func classifyHash(h string) (typ, val string) {
	switch len(h) {
	case 32:
		return IndicatorMD5, strings.ToLower(h)
	case 40:
		return IndicatorSHA1, strings.ToLower(h)
	case 64:
		return IndicatorSHA256, strings.ToLower(h)
	}
	return "", ""
}

// classifyEmail lowercases and validates an email address, dropping one whose
// domain part is noise (for example, a *.local address). The domain is reused
// for host classification so the same drop logic applies.
//
// A bare-numeric domain label (e.g. the "0"/"25" in a Go module pin like
// golang.org/toolchain@v0.0.1-go1.25.0.linux-amd64, which @ makes look like an
// email) disqualifies it: a real email domain never has an all-digit label, so
// this drops the version-string false positive without touching real senders.
func classifyEmail(e string) (typ, val string) {
	e = strings.ToLower(strings.TrimSpace(e))
	at := strings.LastIndexByte(e, '@')
	if at <= 0 || at == len(e)-1 {
		return "", ""
	}
	domain := e[at+1:]
	if htyp, _ := classifyHost(domain); htyp != IndicatorDomain {
		return "", ""
	}
	for _, label := range strings.Split(domain, ".") {
		if isAllDigits(label) {
			return "", ""
		}
	}
	return IndicatorEmail, e
}

// isAllDigits reports whether s is non-empty and every byte is an ASCII digit.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ipv4Boundary reports whether the dotted-quad at s[start:end] stands alone — its
// neighbors are not digits or dots — so it is a whole address, not a slice of a
// longer number/version run. The check is zero-width (it inspects, never
// consumes, the neighbor byte), which is what lets two addresses separated by a
// single byte ("8.8.8.8 9.9.9.9") both pass: the separator is still available as
// the left boundary of the second match.
func ipv4Boundary(s string, start, end int) bool {
	return notByteClass(s, start-1, isDigitOrDot) && notByteClass(s, end, isDigitOrDot)
}

// hashBoundary reports whether the hex run at s[start:end] stands alone — its
// neighbors are not hex digits, '-', or ':'. Excluding hex digits rejects a slice
// of a longer blob; excluding '-'/':' rejects a UUID segment or colon-separated
// fingerprint. Zero-width like ipv4Boundary, so adjacent hashes are both kept.
func hashBoundary(s string, start, end int) bool {
	return notByteClass(s, start-1, isHashBoundaryByte) && notByteClass(s, end, isHashBoundaryByte)
}

// notByteClass reports whether the byte at index i is outside the predicate set,
// treating an out-of-range index (the string edge) as a boundary (true).
func notByteClass(s string, i int, in func(byte) bool) bool {
	if i < 0 || i >= len(s) {
		return true
	}
	return !in(s[i])
}

func isDigitOrDot(b byte) bool { return b >= '0' && b <= '9' || b == '.' }

func isHashBoundaryByte(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F' || b == '-' || b == ':'
}

func trimHostRootDot(host string) string {
	return strings.TrimRight(host, ".")
}

// blankURLs replaces HTTP URLs and other URI authorities with equal-length
// spaces so their userinfo cannot be reclassified as standalone indicators.
func blankURLs(s string) string {
	s = blankMatches(s, urlInText)
	return blankURIAuthorities(s)
}

func blankURIAuthorities(s string) string {
	matches := uriAuthorities(s, -1)
	if len(matches) == 0 {
		return s
	}
	b := []byte(s)
	for _, match := range matches {
		for i := match.start; i < match.end; i++ {
			b[i] = ' '
		}
	}
	return string(b)
}

func blankMatches(s string, re *regexp.Regexp) string {
	locs := re.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	b := []byte(s)
	for _, loc := range locs {
		for i := loc[0]; i < loc[1]; i++ {
			b[i] = ' '
		}
	}
	return string(b)
}

// defangReplacer refangs the common analyst-safe indicator spellings used in threat
// reports so a defanged indicator is recognized and emitted in canonical form.
// It is conservative: only the well-established substitutions (hxxp->http,
// bracketed/parenthesized/braced dots and colons, [@]/(@) for @). NewReplacer matches
// at each position in argument order with no overlapping matches; the only prefix pairs
// here (hxxps/hxxp, hXXps/hXXp) list the longer spelling first so the intended token wins.
var defangReplacer = strings.NewReplacer(
	"hxxps", "https",
	"hXXps", "https",
	"hxxp", "http",
	"hXXp", "http",
	"[.]", ".",
	"(.)", ".",
	"{.}", ".",
	"[dot]", ".",
	"[:]", ":",
	"[://]", "://",
	"[@]", "@",
	"(@)", "@",
)

// refang normalizes defanged indicator spellings to their canonical form before
// extraction. Applied to the whole field, so a defanged URL, IP, domain, or email
// becomes matchable by the same regexes that handle live spellings.
func refang(s string) string {
	if s == "" {
		return s
	}
	return defangReplacer.Replace(s)
}
