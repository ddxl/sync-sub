package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
sub_url: "https://example.com/sub"
headers:
  user-agent: "test-agent/1.0"
  authorization: "Bearer xyz"
exclude_keywords: ["剩余"]
exclude_types: ["hysteria2"]
strip_emoji: true
cf_ip: "104.16.0.1"
cf_replace_server: ["DOMAIN,cf.example.com"]
cf_domains: ["cloudflare.com"]
extra_proxies:
  - name: 香港CF
    type: vless
    server: __CF_IP__
    port: 443
sub_rule_template:
  - MATCH,__LISTENER_PROXY__
listeners:
  - name: mixed-hk
    type: mixed
    port: 7890
    proxy: 香港CF
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.SubURL != "https://example.com/sub" {
		t.Errorf("SubURL = %q, want %q", cfg.SubURL, "https://example.com/sub")
	}
	canon := canonicalizeHeaders(cfg.Headers)
	if canon["User-Agent"] != "test-agent/1.0" {
		t.Errorf("canonicalized User-Agent = %q, want %q", canon["User-Agent"], "test-agent/1.0")
	}
	if canon["Authorization"] != "Bearer xyz" {
		t.Errorf("canonicalized Authorization = %q, want %q", canon["Authorization"], "Bearer xyz")
	}
	if !cfg.StripEmoji {
		t.Error("StripEmoji = false, want true")
	}
	if len(cfg.CFReplaceServer) != 1 || cfg.CFReplaceServer[0] != "DOMAIN,cf.example.com" {
		t.Errorf("CFReplaceServer = %v", cfg.CFReplaceServer)
	}
	if len(cfg.ExtraProxies) != 1 {
		t.Errorf("ExtraProxies len = %d, want 1", len(cfg.ExtraProxies))
	}
	if len(cfg.Listeners) != 1 {
		t.Errorf("Listeners len = %d, want 1", len(cfg.Listeners))
	}
	if len(cfg.SubRuleTemplate) != 1 {
		t.Errorf("SubRuleTemplate len = %d, want 1", len(cfg.SubRuleTemplate))
	}
}

func TestLoadConfigMissingSubURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("output: out.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Error("expected error for missing sub_url, got nil")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := loadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func mustParseCFReplaceRules(t *testing.T, items []string) []cfReplaceRule {
	t.Helper()
	rules, err := parseCFReplaceRules(items)
	if err != nil {
		t.Fatalf("parseCFReplaceRules: %v", err)
	}
	return rules
}

func TestProcessSubscribedProxies(t *testing.T) {
	cfg := &Config{
		ExcludeKeywords: []string{"剩余"},
		ExcludeTypes:    []string{"trojan"},
		CFIP:            "104.16.0.1",
		CFReplaceServer: []string{"DOMAIN,cf.example.com"},
		StripEmoji:      true,
	}
	rules := mustParseCFReplaceRules(t, cfg.CFReplaceServer)
	proxies := []any{
		map[string]any{"name": "🇭🇰 香港 01", "type": "ss", "server": "cf.example.com", "port": 8388},
		map[string]any{"name": "日本 剩余流量", "type": "ss", "server": "jp.example.com", "port": 8388},
		map[string]any{"name": "US 01", "type": "trojan", "server": "us.example.com", "port": 443},
		map[string]any{"name": "🇺🇸 美国 01", "type": "vmess", "server": "us.example.com", "port": 443},
		map[string]any{"name": "  新加坡 01  ", "type": "ss", "server": "sg.example.com", "port": 8388},
	}

	subscribedProxies, subscribedNames := processSubscribedProxies(proxies, cfg, rules)
	if len(subscribedProxies) != 3 {
		t.Fatalf("subscribedProxies len = %d, want 3", len(subscribedProxies))
	}

	m0 := subscribedProxies[0].(map[string]any)
	if m0["server"] != "104.16.0.1" {
		t.Errorf("server = %v, want replaced ip", m0["server"])
	}
	if m0["name"] != "香港 01" {
		t.Errorf("name = %q, want %q", m0["name"], "香港 01")
	}
	m1 := subscribedProxies[1].(map[string]any)
	if m1["server"] != "us.example.com" {
		t.Errorf("server = %v, want untouched", m1["server"])
	}
	m2 := subscribedProxies[2].(map[string]any)
	if m2["name"] != "新加坡 01" {
		t.Errorf("name = %q, want trimmed %q", m2["name"], "新加坡 01")
	}

	wantNames := []string{"香港 01", "美国 01", "新加坡 01"}
	if len(subscribedNames) != 3 || subscribedNames[0] != wantNames[0] || subscribedNames[1] != wantNames[1] || subscribedNames[2] != wantNames[2] {
		t.Errorf("subscribedNames = %v, want %v", subscribedNames, wantNames)
	}
}

func TestStripEmoji(t *testing.T) {
	cases := []struct{ in, want string }{
		{"🇭🇰 香港 01", " 香港 01"},
		{"🚀 节点选择", " 节点选择"},
		{"plain name", "plain name"},
		{"🇺🇸美国", "美国"},
	}
	for _, c := range cases {
		if got := stripEmoji(c.in); got != c.want {
			t.Errorf("stripEmoji(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	cases := []struct {
		in           string
		doStripEmoji bool
		want         string
	}{
		{"  🇭🇰 香港 01  ", true, "香港 01"},
		{"🇭🇰 香港 01", true, "香港 01"},
		{"  🇭🇰 香港 01  ", false, "🇭🇰 香港 01"},
		{"  extra  ", false, "extra"},
		{"🇺🇸美国", true, "美国"},
		{"plain name", true, "plain name"},
	}
	for _, c := range cases {
		if got := normalizeName(c.in, c.doStripEmoji); got != c.want {
			t.Errorf("normalizeName(%q, %v) = %q, want %q", c.in, c.doStripEmoji, got, c.want)
		}
	}
}

func TestParseCFReplaceRules(t *testing.T) {
	rules := mustParseCFReplaceRules(t, []string{
		"DOMAIN,cf.example.com",
		"DOMAIN-SUFFIX, pages.dev",
		"DOMAIN-PREFIX, cf-",
		"DOMAIN-REGEXP,(?i)^.+\\.workers\\.dev$",
		"",
	})
	if len(rules) != 4 {
		t.Fatalf("rules len = %d, want 4", len(rules))
	}
	if rules[0].kind != "DOMAIN" || rules[0].payload != "cf.example.com" {
		t.Errorf("DOMAIN rule = %+v", rules[0])
	}
	if rules[1].kind != "DOMAIN-SUFFIX" || rules[1].payload != "pages.dev" {
		t.Errorf("DOMAIN-SUFFIX rule = %+v", rules[1])
	}
	if rules[2].kind != "DOMAIN-PREFIX" || rules[2].payload != "cf-" {
		t.Errorf("DOMAIN-PREFIX rule = %+v", rules[2])
	}
	if rules[3].kind != "DOMAIN-REGEXP" || rules[3].re == nil {
		t.Errorf("DOMAIN-REGEXP rule = %+v", rules[3])
	}

	cases := []string{
		"cf.example.com",
		"DOMAIN,",
		"FOO,bar",
		"DOMAIN-REGEXP,[",
	}
	for _, item := range cases {
		if _, err := parseCFReplaceRules([]string{item}); err == nil {
			t.Errorf("parseCFReplaceRules(%q) expected error", item)
		}
	}
}

func TestMatchCFReplace(t *testing.T) {
	rules := mustParseCFReplaceRules(t, []string{
		"DOMAIN,cdn.example.com",
		"DOMAIN-SUFFIX,pages.dev",
		"DOMAIN-PREFIX,cf-",
		"DOMAIN-REGEXP,(?i)^.+\\.workers\\.dev$",
	})
	cases := []struct {
		host string
		want bool
	}{
		{"cdn.example.com", true},
		{"CDN.EXAMPLE.COM", true},
		{"sub.cdn.example.com", false},
		{"pages.dev", true},
		{"foo.pages.dev", true},
		{"notpages.dev", false},
		{"cf-edge.example.com", true},
		{"CF-edge.example.com", true},
		{"xcf-edge.example.com", false},
		{"abc.workers.dev", true},
		{"ABC.WORKERS.DEV", true},
		{"workers.dev", false},
		{"", false},
	}
	for _, c := range cases {
		if got := matchCFReplace(c.host, rules); got != c.want {
			t.Errorf("matchCFReplace(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestProcessExtraProxies(t *testing.T) {
	cfg := &Config{
		CFIP: "1.2.3.4",
		ExtraProxies: []map[string]any{
			{"name": "  香港CF  ", "type": "vless", "server": "__CF_IP__", "port": 443, "sni": "__CF_IP__"},
			{"name": "美国CF", "type": "vless", "server": " __CF_IP__ ", "port": 443},
			{"name": "直连", "type": "vless", "server": "example.com", "port": 443},
			{"name": "部分", "type": "vless", "server": "prefix-__CF_IP__", "port": 443},
		},
	}
	out, names, err := processExtraProxies(cfg)
	if err != nil {
		t.Fatalf("processExtraProxies: %v", err)
	}
	if out[0]["server"] != "1.2.3.4" {
		t.Errorf("exact placeholder not replaced: %v", out[0]["server"])
	}
	if out[0]["sni"] != "__CF_IP__" {
		t.Errorf("sni should stay, got %v", out[0]["sni"])
	}
	if out[0]["name"] != "香港CF" {
		t.Errorf("name = %q, want trimmed 香港CF", out[0]["name"])
	}
	if out[1]["server"] != "1.2.3.4" {
		t.Errorf("trimmed placeholder not replaced: %v", out[1]["server"])
	}
	if out[2]["server"] != "example.com" {
		t.Errorf("normal server touched: %v", out[2]["server"])
	}
	if out[3]["server"] != "prefix-__CF_IP__" {
		t.Errorf("partial placeholder should stay, got %v", out[3]["server"])
	}
	wantNames := []string{"香港CF", "美国CF", "直连", "部分"}
	if len(names) != 4 || names[0] != wantNames[0] || names[1] != wantNames[1] || names[2] != wantNames[2] || names[3] != wantNames[3] {
		t.Errorf("names = %v, want %v", names, wantNames)
	}
	if cfg.ExtraProxies[0]["name"] != "  香港CF  " {
		t.Errorf("original extra_proxies mutated: %v", cfg.ExtraProxies[0]["name"])
	}
}

func TestProcessExtraProxiesMissingCFIP(t *testing.T) {
	cfg := &Config{
		ExtraProxies: []map[string]any{
			{"name": "x", "server": "__CF_IP__"},
		},
	}
	if _, _, err := processExtraProxies(cfg); err == nil {
		t.Error("expected error when cf_ip is empty")
	}
}

func TestExpandNamePlaceholders(t *testing.T) {
	replacements := map[string][]string{
		subscribedPlaceholder: {"HK 01", "US 01"},
		extraPlaceholder:      {"CF 01"},
	}

	if got := expandNamePlaceholders("hello", replacements); got != "hello" {
		t.Errorf("plain string = %v", got)
	}
	if got, ok := expandNamePlaceholders(subscribedPlaceholder, replacements).([]string); !ok || len(got) != 2 || got[0] != "HK 01" {
		t.Errorf("subscribed placeholder = %v", got)
	}
	if got, ok := expandNamePlaceholders(extraPlaceholder, replacements).([]string); !ok || len(got) != 1 || got[0] != "CF 01" {
		t.Errorf("extra placeholder = %v", got)
	}

	list := []any{"DIRECT", extraPlaceholder, subscribedPlaceholder, "REJECT"}
	expanded := expandNamePlaceholders(list, replacements).([]any)
	want := []any{"DIRECT", "CF 01", "HK 01", "US 01", "REJECT"}
	if len(expanded) != 5 {
		t.Fatalf("expanded len = %d, want 5", len(expanded))
	}
	for i := range want {
		if expanded[i] != want[i] {
			t.Errorf("expanded = %v, want %v", expanded, want)
			break
		}
	}

	m := map[string]any{"proxies": []any{extraPlaceholder, subscribedPlaceholder}}
	em := expandNamePlaceholders(m, replacements).(map[string]any)
	inner := em["proxies"].([]any)
	if len(inner) != 3 || inner[0] != "CF 01" || inner[1] != "HK 01" || inner[2] != "US 01" {
		t.Errorf("map expanded = %v", em)
	}
}

func TestProcessListeners(t *testing.T) {
	cfg := &Config{
		SubRuleTemplate: []any{"GEOIP,CN,DIRECT", "MATCH,__LISTENER_PROXY__"},
		Listeners: []map[string]any{
			{"name": " mixed-hk ", "type": "mixed", "port": 7890, "proxy": " 香港CF "},
			{"name": "mixed-us", "type": "mixed", "port": 7891, "proxy": "美国CF", "udp": true},
		},
	}
	listeners, subRules, groups, err := processListeners(cfg)
	if err != nil {
		t.Fatalf("processListeners: %v", err)
	}
	if len(listeners) != 2 {
		t.Fatalf("listeners len = %d, want 2", len(listeners))
	}

	hk := listeners[0].(orderedMap).m
	if hk["name"] != "mixed-hk" {
		t.Errorf("name = %q, want mixed-hk", hk["name"])
	}
	if hk["rule"] != "sub-rule-mixed-hk" {
		t.Errorf("rule = %v, want sub-rule-mixed-hk", hk["rule"])
	}
	if _, ok := hk["proxy"]; ok {
		t.Errorf("proxy should be removed, got %v", hk["proxy"])
	}

	us := listeners[1].(orderedMap).m
	if us["rule"] != "sub-rule-mixed-us" {
		t.Errorf("rule = %v, want sub-rule-mixed-us", us["rule"])
	}
	if us["udp"] != true {
		t.Errorf("udp should pass through, got %v", us["udp"])
	}

	om := subRules.(orderedMap)
	hkRules := om.m["sub-rule-mixed-hk"].([]any)
	if len(hkRules) != 2 || hkRules[0] != "GEOIP,CN,DIRECT" || hkRules[1] != "MATCH,hidden-proxy-香港CF" {
		t.Errorf("mixed-hk rules = %v", hkRules)
	}
	usRules := om.m["sub-rule-mixed-us"].([]any)
	if len(usRules) != 2 || usRules[1] != "MATCH,hidden-proxy-美国CF" {
		t.Errorf("mixed-us rules = %v", usRules)
	}
	if len(om.prependKeys) != 2 || om.prependKeys[0] != "sub-rule-mixed-hk" || om.prependKeys[1] != "sub-rule-mixed-us" {
		t.Errorf("sub-rule key order = %v", om.prependKeys)
	}

	if len(groups) != 2 {
		t.Fatalf("groups len = %d, want 2", len(groups))
	}
	g0 := groups[0].(orderedMap).m
	if g0["name"] != "hidden-proxy-香港CF" || g0["type"] != "select" || g0["hidden"] != true {
		t.Errorf("group0 = %v", g0)
	}
	g0proxies, _ := g0["proxies"].([]any)
	if len(g0proxies) != 1 || g0proxies[0] != "香港CF" {
		t.Errorf("group0 proxies = %v", g0proxies)
	}
	g1 := groups[1].(orderedMap).m
	if g1["name"] != "hidden-proxy-美国CF" {
		t.Errorf("group1 name = %v, want hidden-proxy-美国CF", g1["name"])
	}
}

func TestProcessListenersSharedProxyDedup(t *testing.T) {
	cfg := &Config{
		SubRuleTemplate: []any{"MATCH,__LISTENER_PROXY__"},
		Listeners: []map[string]any{
			{"name": "port-a", "type": "mixed", "port": 7890, "proxy": "main-us"},
			{"name": "port-b", "type": "mixed", "port": 7891, "proxy": "main-us"},
			{"name": "port-c", "type": "mixed", "port": 7892, "proxy": "main-hk"},
		},
	}
	listeners, subRules, groups, err := processListeners(cfg)
	if err != nil {
		t.Fatalf("processListeners: %v", err)
	}
	if len(listeners) != 3 {
		t.Fatalf("listeners len = %d, want 3", len(listeners))
	}
	if len(groups) != 2 {
		t.Fatalf("groups len = %d, want 2 (deduped by proxy)", len(groups))
	}
	om := subRules.(orderedMap)
	a := om.m["sub-rule-port-a"].([]any)
	b := om.m["sub-rule-port-b"].([]any)
	c := om.m["sub-rule-port-c"].([]any)
	if a[0] != "MATCH,hidden-proxy-main-us" || b[0] != "MATCH,hidden-proxy-main-us" {
		t.Errorf("shared proxy MATCH mismatch: a=%v b=%v", a, b)
	}
	if c[0] != "MATCH,hidden-proxy-main-hk" {
		t.Errorf("other proxy MATCH = %v", c)
	}
}

func TestProcessListenersNoTemplate(t *testing.T) {
	cfg := &Config{
		Listeners: []map[string]any{
			{"name": "mixed-hk", "type": "mixed", "port": 7890, "proxy": "香港CF"},
		},
	}
	listeners, subRules, groups, err := processListeners(cfg)
	if err != nil {
		t.Fatalf("processListeners: %v", err)
	}
	if subRules != nil {
		t.Errorf("subRules = %v, want nil", subRules)
	}
	if groups != nil {
		t.Errorf("groups = %v, want nil", groups)
	}
	m := listeners[0].(orderedMap).m
	if m["proxy"] != "香港CF" {
		t.Errorf("proxy should stay without template, got %v", m["proxy"])
	}
	if _, ok := m["rule"]; ok {
		t.Errorf("rule should not be set without template, got %v", m["rule"])
	}
}

func TestProcessListenersErrors(t *testing.T) {
	if _, _, _, err := processListeners(&Config{
		SubRuleTemplate: []any{"MATCH,__LISTENER_PROXY__"},
		Listeners: []map[string]any{
			{"name": "a", "proxy": "p"},
			{"name": "a", "proxy": "q"},
		},
	}); err == nil {
		t.Error("expected duplicate name error")
	}
	if _, _, _, err := processListeners(&Config{
		SubRuleTemplate: []any{"MATCH,__LISTENER_PROXY__"},
		Listeners: []map[string]any{
			{"name": "a"},
		},
	}); err == nil {
		t.Error("expected missing proxy error")
	}
	if _, _, _, err := processListeners(&Config{
		SubRuleTemplate: []any{"MATCH,__LISTENER_PROXY__"},
		Listeners: []map[string]any{
			{"name": "   "},
		},
	}); err == nil {
		t.Error("expected missing name error")
	}
}

func TestMergeHosts(t *testing.T) {
	cfHosts := map[string]any{
		"cloudflare.com":   "104.16.0.1",
		"*.cloudflare.com": "104.16.0.1",
	}
	inject := map[string]any{"cloudflare.com": "1.0.0.1"}
	merged := mergeHosts(cfHosts, inject)
	if merged["cloudflare.com"] != "1.0.0.1" {
		t.Errorf("inject should win, got %v", merged["cloudflare.com"])
	}
	if merged["*.cloudflare.com"] != "104.16.0.1" {
		t.Errorf("cf entry should stay, got %v", merged["*.cloudflare.com"])
	}
}

func TestBuildCFHostsAndRules(t *testing.T) {
	hosts := buildCFHosts("104.16.0.1", []string{"cloudflare.com", "cdn.example.com"})
	if hosts["cloudflare.com"] != "104.16.0.1" || hosts["*.cloudflare.com"] != "104.16.0.1" {
		t.Errorf("bare+wildcard missing: %v", hosts)
	}
	if hosts["cdn.example.com"] != "104.16.0.1" || hosts["*.cdn.example.com"] != "104.16.0.1" {
		t.Errorf("bare+wildcard missing for second domain: %v", hosts)
	}

	rules := buildCFRules([]string{"cloudflare.com"})
	if len(rules) != 1 || rules[0] != "DOMAIN-SUFFIX,cloudflare.com,DIRECT" {
		t.Errorf("rules = %v", rules)
	}
}

// marshalKeyOrder 序列化顶层 map 并返回指定路径下第一个 mapping 的键顺序
func marshalKeyOrder(t *testing.T, m map[string]any, path ...string) []string {
	t.Helper()
	out, err := yaml.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	node := &doc
	if len(doc.Content) > 0 {
		node = doc.Content[0]
	}
	for _, p := range path {
		switch node.Kind {
		case yaml.MappingNode:
			found := false
			for i := 0; i < len(node.Content); i += 2 {
				if node.Content[i].Value == p {
					node = node.Content[i+1]
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("key %q not found", p)
			}
		case yaml.SequenceNode:
			idx, err := strconv.Atoi(p)
			if err != nil || idx < 0 || idx >= len(node.Content) {
				t.Fatalf("invalid sequence index %q", p)
			}
			node = node.Content[idx]
		default:
			t.Fatalf("unexpected node kind %d at path %q", node.Kind, p)
		}
	}
	if node.Kind != yaml.MappingNode {
		t.Fatalf("expected mapping at end of path, got kind %d", node.Kind)
	}
	var keys []string
	for i := 0; i < len(node.Content); i += 2 {
		keys = append(keys, node.Content[i].Value)
	}
	return keys
}

func TestProxyFieldOrder(t *testing.T) {
	output := map[string]any{
		"proxies": []any{
			orderedMap{m: map[string]any{
				"name":     "local-4045",
				"type":     "socks5",
				"server":   "127.0.0.1",
				"port":     4045,
				"udp":      false,
				"password": "x",
			}, prependKeys: proxyOrder},
		},
	}
	keys := marshalKeyOrder(t, output, "proxies", "0")
	want := []string{"name", "type", "server", "port", "password", "udp"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("proxy key order = %v, want %v", keys, want)
	}
}

func TestProxyGroupFieldOrder(t *testing.T) {
	output := map[string]any{
		"proxy-groups": []any{
			orderedMap{m: map[string]any{
				"name":     "Auto",
				"type":     "url-test",
				"url":      "http://example.com/generate_204",
				"interval": 300,
				"proxies":  []any{"HK 01", "US 01"},
			}, appendKeys: []string{"proxies"}},
		},
	}
	keys := marshalKeyOrder(t, output, "proxy-groups", "0")
	want := []string{"interval", "name", "type", "url", "proxies"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("proxy-group key order = %v, want %v", keys, want)
	}
}

func TestListenerFieldOrder(t *testing.T) {
	output := map[string]any{
		"listeners": []any{
			orderedMap{m: map[string]any{
				"name": "mixed-hk",
				"type": "mixed",
				"port": 7890,
				"udp":  true,
				"rule": "sub-rule-mixed-hk",
			}, prependKeys: listenerOrder},
		},
	}
	keys := marshalKeyOrder(t, output, "listeners", "0")
	want := []string{"name", "type", "port", "rule", "udp"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("listener key order = %v, want %v", keys, want)
	}
}

func TestHiddenProxyGroupFieldOrder(t *testing.T) {
	output := map[string]any{
		"proxy-groups": []any{
			orderedMap{
				m: map[string]any{
					"name":    "hidden-proxy-main-us",
					"type":    "select",
					"hidden":  true,
					"proxies": []any{"main-us"},
				},
				prependKeys: []string{"name", "type", "hidden"},
				appendKeys:  []string{"proxies"},
			},
		},
	}
	keys := marshalKeyOrder(t, output, "proxy-groups", "0")
	want := []string{"name", "type", "hidden", "proxies"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("hidden proxy-group key order = %v, want %v", keys, want)
	}
}

func TestEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "test-agent/1.0" {
			t.Errorf("User-Agent = %q, want test-agent/1.0", r.Header.Get("User-Agent"))
		}
		if r.Header.Get("Authorization") != "Bearer xyz" {
			t.Errorf("Authorization = %q, want Bearer xyz", r.Header.Get("Authorization"))
		}
		w.Write([]byte(`
proxies:
  - name: "🇭🇰 香港 01"
    type: ss
    server: "cf.example.com"
    port: 8388
    cipher: "aes-256-gcm"
    password: "a"
  - name: "日本 剩余流量"
    type: ss
    server: "jp.example.com"
    port: 8388
    password: "b"
  - name: "US 01"
    type: trojan
    server: "us.example.com"
    port: 443
    password: "c"
`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	cfgContent := `
sub_url: "` + srv.URL + `"
headers:
  user-agent: "test-agent/1.0"
  authorization: "Bearer xyz"
exclude_keywords: ["剩余"]
exclude_types: ["trojan"]
strip_emoji: true
cf_ip: "104.16.0.1"
cf_replace_server:
  - DOMAIN,cf.example.com
cf_domains: ["cloudflare.com"]
extra_proxies:
  - name: " 本地节点 "
    type: socks5
    server: __CF_IP__
    port: 1080
sub_rule_template:
  - GEOIP,CN,DIRECT
  - MATCH,__LISTENER_PROXY__
listeners:
  - name: mixed-local
    type: mixed
    port: 7890
    proxy: 本地节点
inject:
  proxy-groups:
    - name: Proxy
      type: select
      proxies:
        - DIRECT
        - __EXTRA__
        - __SUBSCRIBED__
  rules:
    - "MATCH,Proxy"
  hosts:
    cloudflare.com: "1.0.0.1"
`
	if err := os.WriteFile(configPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	cfReplaceRules, err := parseCFReplaceRules(cfg.CFReplaceServer)
	if err != nil {
		t.Fatalf("parseCFReplaceRules: %v", err)
	}
	client := &http.Client{Transport: &headerTransport{rt: &http.Transport{Proxy: http.ProxyFromEnvironment}, headers: canonicalizeHeaders(cfg.Headers)}}
	body, err := fetchSub(client, cfg.SubURL)
	if err != nil {
		t.Fatalf("fetchSub: %v", err)
	}
	var sub map[string]any
	if err := yaml.Unmarshal(body, &sub); err != nil {
		t.Fatalf("unmarshal sub: %v", err)
	}
	rawProxies, _ := sub["proxies"].([]any)
	subscribedProxies, subscribedNames := processSubscribedProxies(rawProxies, cfg, cfReplaceRules)
	extraProxies, extraNames, err := processExtraProxies(cfg)
	if err != nil {
		t.Fatalf("processExtraProxies: %v", err)
	}

	output := make(map[string]any)
	proxies := make([]any, 0, len(extraProxies)+len(subscribedProxies))
	for _, p := range extraProxies {
		proxies = append(proxies, orderedMap{m: p, prependKeys: proxyOrder})
	}
	for _, p := range subscribedProxies {
		m := p.(map[string]any)
		proxies = append(proxies, orderedMap{m: m, prependKeys: proxyOrder})
	}
	output["proxies"] = proxies

	replacements := map[string][]string{
		subscribedPlaceholder: subscribedNames,
		extraPlaceholder:      extraNames,
	}
	for k, v := range cfg.Inject {
		if k == "proxy-groups" {
			groups := v.([]any)
			expanded := expandNamePlaceholders(groups, replacements).([]any)
			out2 := make([]any, 0, len(expanded))
			for _, g := range expanded {
				gm := g.(map[string]any)
				out2 = append(out2, orderedMap{m: gm, appendKeys: []string{"proxies"}})
			}
			output[k] = out2
			continue
		}
		output[k] = expandNamePlaceholders(v, replacements)
	}

	listeners, subRules, listenerGroups, err := processListeners(cfg)
	if err != nil {
		t.Fatalf("processListeners: %v", err)
	}
	output["listeners"] = listeners
	output["sub-rules"] = subRules
	if len(listenerGroups) > 0 {
		output["proxy-groups"] = append(toAnySlice(output["proxy-groups"]), listenerGroups...)
	}

	cfDomains := prepareDomains(cfg.CFDomains)
	output["hosts"] = mergeHosts(buildCFHosts(cfg.CFIP, cfDomains), output["hosts"])
	rules := buildCFRules(cfDomains)
	rules = append(rules, toAnySlice(output["rules"])...)
	output["rules"] = rules

	final, err := marshalOutput(output)
	if err != nil {
		t.Fatalf("marshalOutput: %v", err)
	}
	finalStr := string(final)

	if !strings.Contains(finalStr, "name: 香港 01") {
		t.Errorf("emoji not stripped: %s", finalStr)
	}
	if !strings.Contains(finalStr, "name: 本地节点") {
		t.Errorf("extra proxy missing: %s", finalStr)
	}
	if strings.Contains(finalStr, "剩余") || strings.Contains(finalStr, "trojan") {
		t.Errorf("filtered proxies still present: %s", finalStr)
	}
	if !strings.Contains(finalStr, "server: 104.16.0.1") {
		t.Errorf("server not replaced: %s", finalStr)
	}
	if !strings.Contains(finalStr, "- 香港 01") {
		t.Errorf("subscribed placeholder not expanded: %s", finalStr)
	}
	if !strings.Contains(finalStr, "- 本地节点") {
		t.Errorf("extra placeholder not expanded: %s", finalStr)
	}
	if !strings.Contains(finalStr, "cloudflare.com: 1.0.0.1") {
		t.Errorf("inject hosts missing: %s", finalStr)
	}
	if !strings.Contains(finalStr, "DOMAIN-SUFFIX,cloudflare.com,DIRECT") {
		t.Errorf("cf rule missing: %s", finalStr)
	}
	if !strings.Contains(finalStr, "MATCH,Proxy") {
		t.Errorf("inject rules missing: %s", finalStr)
	}
	if !strings.Contains(finalStr, "rule: sub-rule-mixed-local") {
		t.Errorf("listener rule missing: %s", finalStr)
	}
	if !strings.Contains(finalStr, "MATCH,hidden-proxy-本地节点") {
		t.Errorf("listener proxy placeholder not expanded: %s", finalStr)
	}
	if !strings.Contains(finalStr, "name: hidden-proxy-本地节点") {
		t.Errorf("hidden proxy group missing: %s", finalStr)
	}

	hasTwoSpaceIndent := false
	for _, line := range strings.Split(finalStr, "\n") {
		if line == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent%2 != 0 {
			t.Errorf("odd indentation (%d spaces): %q", indent, line)
		}
		if indent == 2 {
			hasTwoSpaceIndent = true
		}
	}
	if !hasTwoSpaceIndent {
		t.Errorf("no 2-space indented lines in output:\n%s", finalStr)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(final, &parsed); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	hosts, _ := parsed["hosts"].(map[string]any)
	if hosts["*.cloudflare.com"] != "104.16.0.1" {
		t.Errorf("cf wildcard host missing: %v", hosts)
	}
	outProxies, _ := parsed["proxies"].([]any)
	if len(outProxies) != 2 {
		t.Fatalf("proxies len = %d, want 2", len(outProxies))
	}
	p0 := outProxies[0].(map[string]any)
	if p0["name"] != "本地节点" || p0["server"] != "104.16.0.1" {
		t.Errorf("extra proxy = %v", p0)
	}
	p1 := outProxies[1].(map[string]any)
	if p1["name"] != "香港 01" || p1["server"] != "104.16.0.1" {
		t.Errorf("subscribed proxy = %v", p1)
	}
	groups, _ := parsed["proxy-groups"].([]any)
	if len(groups) != 2 {
		t.Fatalf("proxy-groups len = %d, want 2", len(groups))
	}
	group0 := groups[0].(map[string]any)
	groupProxies, _ := group0["proxies"].([]any)
	wantGroupProxies := []any{"DIRECT", "本地节点", "香港 01"}
	if len(groupProxies) != 3 || groupProxies[0] != wantGroupProxies[0] || groupProxies[1] != wantGroupProxies[1] || groupProxies[2] != wantGroupProxies[2] {
		t.Errorf("proxy-groups proxies = %v, want %v", groupProxies, wantGroupProxies)
	}
	hidden := groups[1].(map[string]any)
	if hidden["name"] != "hidden-proxy-本地节点" || hidden["type"] != "select" || hidden["hidden"] != true {
		t.Errorf("hidden group = %v", hidden)
	}
	hiddenProxies, _ := hidden["proxies"].([]any)
	if len(hiddenProxies) != 1 || hiddenProxies[0] != "本地节点" {
		t.Errorf("hidden group proxies = %v", hiddenProxies)
	}
	rules, _ = parsed["rules"].([]any)
	if len(rules) != 2 || rules[0] != "DOMAIN-SUFFIX,cloudflare.com,DIRECT" || rules[1] != "MATCH,Proxy" {
		t.Errorf("rules = %v, want CF rule first then inject rules", rules)
	}
	ls, _ := parsed["listeners"].([]any)
	if len(ls) != 1 {
		t.Fatalf("listeners len = %d, want 1", len(ls))
	}
	l0 := ls[0].(map[string]any)
	if l0["rule"] != "sub-rule-mixed-local" {
		t.Errorf("listener rule = %v", l0["rule"])
	}
	if _, ok := l0["proxy"]; ok {
		t.Errorf("listener proxy should be removed: %v", l0)
	}
	parsedSubRules, _ := parsed["sub-rules"].(map[string]any)
	localRules, _ := parsedSubRules["sub-rule-mixed-local"].([]any)
	if len(localRules) != 2 || localRules[0] != "GEOIP,CN,DIRECT" || localRules[1] != "MATCH,hidden-proxy-本地节点" {
		t.Errorf("sub-rules = %v", parsedSubRules)
	}
}
