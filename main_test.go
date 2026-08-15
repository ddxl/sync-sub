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
cf_replace_server: ["cf.example.com"]
cf_domains: ["cloudflare.com"]
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
	if len(cfg.CFReplaceServer) != 1 || cfg.CFReplaceServer[0] != "cf.example.com" {
		t.Errorf("CFReplaceServer = %v", cfg.CFReplaceServer)
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

func TestProcessProxies(t *testing.T) {
	cfg := &Config{
		ExcludeKeywords: []string{"剩余"},
		ExcludeTypes:    []string{"trojan"},
		CFIP:            "104.16.0.1",
		CFReplaceServer: []string{"cf.example.com"},
		StripEmoji:      true,
	}
	proxies := []any{
		map[string]any{"name": "🇭🇰 香港 01", "type": "ss", "server": "cf.example.com", "port": 8388},
		map[string]any{"name": "日本 剩余流量", "type": "ss", "server": "jp.example.com", "port": 8388},
		map[string]any{"name": "US 01", "type": "trojan", "server": "us.example.com", "port": 443},
		map[string]any{"name": "🇺🇸 美国 01", "type": "vmess", "server": "us.example.com", "port": 443},
	}

	filtered, nodeNames := processProxies(proxies, cfg)
	if len(filtered) != 2 {
		t.Fatalf("filtered len = %d, want 2", len(filtered))
	}

	// server 替换 + 去 emoji
	m0 := filtered[0].(map[string]any)
	if m0["server"] != "104.16.0.1" {
		t.Errorf("server = %v, want replaced ip", m0["server"])
	}
	if m0["name"] != "香港 01" {
		t.Errorf("name = %q, want %q", m0["name"], "香港 01")
	}
	// 未命中替换域名的保持原样
	m1 := filtered[1].(map[string]any)
	if m1["server"] != "us.example.com" {
		t.Errorf("server = %v, want untouched", m1["server"])
	}

	wantNames := []string{"香港 01", "美国 01"}
	if len(nodeNames) != 2 || nodeNames[0] != wantNames[0] || nodeNames[1] != wantNames[1] {
		t.Errorf("nodeNames = %v, want %v", nodeNames, wantNames)
	}
}

func TestStripEmoji(t *testing.T) {
	cases := []struct{ in, want string }{
		{"🇭🇰 香港 01", "香港 01"},
		{"🚀 节点选择", "节点选择"},
		{"plain name", "plain name"},
		{"🇺🇸美国", "美国"},
	}
	for _, c := range cases {
		if got := stripEmoji(c.in); got != c.want {
			t.Errorf("stripEmoji(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMatchesDomains(t *testing.T) {
	domains := prepareDomains([]string{"CloudFlare.com", "example.com"})
	cases := []struct {
		host string
		want bool
	}{
		{"cloudflare.com", true},
		{"sub.cloudflare.com", true},
		{"deep.sub.CLOUDFLARE.com", true},
		{"example.com", true},
		{"fakecloudflare.com", false},
		{"notexample.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := matchesDomains(c.host, domains); got != c.want {
			t.Errorf("matchesDomains(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestExpandPlaceholder(t *testing.T) {
	names := []string{"HK 01", "US 01"}

	// 字符串直接返回
	if got := expandPlaceholder("hello", names); got != "hello" {
		t.Errorf("plain string = %v", got)
	}
	// 占位符展开为 []string
	if got, ok := expandPlaceholder(placeholder, names).([]string); !ok || len(got) != 2 || got[0] != "HK 01" {
		t.Errorf("placeholder = %v", got)
	}
	// 列表递归
	list := []any{"DIRECT", placeholder, "REJECT"}
	expanded := expandPlaceholder(list, names).([]any)
	if len(expanded) != 4 {
		t.Fatalf("expanded len = %d, want 4", len(expanded))
	}
	if expanded[0] != "DIRECT" || expanded[1] != "HK 01" || expanded[2] != "US 01" || expanded[3] != "REJECT" {
		t.Errorf("expanded = %v", expanded)
	}
	// map 递归
	m := map[string]any{"proxies": []any{placeholder}}
	em := expandPlaceholder(m, names).(map[string]any)
	inner := em["proxies"].([]any)
	if len(inner) != 2 || inner[0] != "HK 01" {
		t.Errorf("map expanded = %v", em)
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

func TestEndToEnd(t *testing.T) {
	// 本地订阅服务器
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
cf_replace_server: ["cf.example.com"]
cf_domains: ["cloudflare.com"]
inject:
  proxy-groups:
    - name: Proxy
      type: select
      proxies:
        - DIRECT
        - __SUBSCRIBED__
  rules:
    - "MATCH,Proxy"
  hosts:
    cloudflare.com: "1.0.0.1"
`
	if err := os.WriteFile(configPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, _ := loadConfig(configPath)
	client := &http.Client{Transport: &headerTransport{rt: &http.Transport{Proxy: http.ProxyFromEnvironment}, headers: canonicalizeHeaders(cfg.Headers)}}
	body, _ := fetchSub(client, cfg.SubURL)
	var sub map[string]any
	yaml.Unmarshal(body, &sub)
	rawProxies, _ := sub["proxies"].([]any)
	filtered, nodeNames := processProxies(rawProxies, cfg)
	output := make(map[string]any)
	proxies := make([]any, 0, len(filtered))
	for _, p := range filtered {
		m := p.(map[string]any)
		proxies = append(proxies, orderedMap{m: m, prependKeys: proxyOrder})
	}
	output["proxies"] = proxies
	for k, v := range cfg.Inject {
		if k == "proxy-groups" {
			groups := v.([]any)
			expanded := expandPlaceholder(groups, nodeNames).([]any)
			out2 := make([]any, 0, len(expanded))
			for _, g := range expanded {
				gm := g.(map[string]any)
				out2 = append(out2, orderedMap{m: gm, appendKeys: []string{"proxies"}})
			}
			output[k] = out2
			continue
		}
		output[k] = expandPlaceholder(v, nodeNames)
	}
	cfDomains := prepareDomains(cfg.CFDomains)
	output["hosts"] = mergeHosts(buildCFHosts(cfg.CFIP, cfDomains), output["hosts"])
	rules := buildCFRules(cfDomains)
	rules = append(rules, toAnySlice(output["rules"])...)
	output["rules"] = rules

	final, _ := marshalOutput(output)
	finalStr := string(final)

	// 断言
	if !strings.Contains(finalStr, "name: 香港 01") {
		t.Errorf("emoji not stripped: %s", finalStr)
	}
	if strings.Contains(finalStr, "剩余") || strings.Contains(finalStr, "trojan") {
		t.Errorf("filtered proxies still present: %s", finalStr)
	}
	if !strings.Contains(finalStr, "server: 104.16.0.1") {
		t.Errorf("server not replaced: %s", finalStr)
	}
	if !strings.Contains(finalStr, "- 香港 01") {
		t.Errorf("placeholder not expanded: %s", finalStr)
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
	// 缩进断言:每行缩进必须是 2 的倍数,且存在 2 空格缩进的行
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

	// 结构断言：hosts 通配条目、rules 顺序、proxy-groups proxies 内容
	var parsed map[string]any
	if err := yaml.Unmarshal(final, &parsed); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	hosts, _ := parsed["hosts"].(map[string]any)
	if hosts["*.cloudflare.com"] != "104.16.0.1" {
		t.Errorf("cf wildcard host missing: %v", hosts)
	}
	groups, _ := parsed["proxy-groups"].([]any)
	if len(groups) != 1 {
		t.Fatalf("proxy-groups len = %d, want 1", len(groups))
	}
	group0 := groups[0].(map[string]any)
	groupProxies, _ := group0["proxies"].([]any)
	wantGroupProxies := []any{"DIRECT", "香港 01"}
	if len(groupProxies) != 2 || groupProxies[0] != wantGroupProxies[0] || groupProxies[1] != wantGroupProxies[1] {
		t.Errorf("proxy-groups proxies = %v, want %v", groupProxies, wantGroupProxies)
	}
	rules, _ = parsed["rules"].([]any)
	if len(rules) != 2 || rules[0] != "DOMAIN-SUFFIX,cloudflare.com,DIRECT" || rules[1] != "MATCH,Proxy" {
		t.Errorf("rules = %v, want CF rule first then inject rules", rules)
	}
}
