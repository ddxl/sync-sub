package main

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	subscribedPlaceholder    = "__SUBSCRIBED__"
	extraPlaceholder         = "__EXTRA__"
	cfIPPlaceholder          = "__CF_IP__"
	listenerProxyPlaceholder = "__LISTENER_PROXY__"
	listenerSubRulePrefix    = "sub-rule-"
	listenerGroupPrefix      = "hidden-proxy-"
)

// emoji unicode 区间
var emojiRe = regexp.MustCompile(`[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{2B00}-\x{2BFF}\x{1F1E6}-\x{1F1FF}\x{200D}\x{2300}-\x{23FF}\x{2B50}\x{2190}-\x{21FF}\x{FE00}-\x{FE0F}]`)

type Config struct {
	SubURL          string            `yaml:"sub_url"`
	Output          string            `yaml:"output"`
	Headers         map[string]string `yaml:"headers"`
	CFIP            string            `yaml:"cf_ip"`
	ExcludeKeywords []string          `yaml:"exclude_keywords"`
	ExcludeTypes    []string          `yaml:"exclude_types"`
	ExtraProxies    []map[string]any  `yaml:"extra_proxies"`
	CFReplaceServer []string          `yaml:"cf_replace_server"`
	CFDomains       []string          `yaml:"cf_domains"`
	StripEmoji      bool              `yaml:"strip_emoji"`
	Inject          map[string]any    `yaml:"inject"`
	SubRuleTemplate []any             `yaml:"sub_rule_template"`
	Listeners       []map[string]any  `yaml:"listeners"`
}

type headerTransport struct {
	rt      http.RoundTripper
	headers map[string]string
}

type cfReplaceRule struct {
	kind    string
	payload string
	re      *regexp.Regexp
}

// canonicalizeHeaders 用 http.Header 的规范形式（首字母大写）统一键名，
// 避免 user-agent / user-Agent 等大小写变体查不到
func canonicalizeHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[http.CanonicalHeaderKey(k)] = v
	}
	return out
}

func (t *headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	return t.rt.RoundTrip(r)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	os.Exit(1)
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置 %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置 %s: %w", path, err)
	}
	if cfg.SubURL == "" {
		return nil, fmt.Errorf("配置缺少 sub_url")
	}
	return &cfg, nil
}

func fetchSub(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求订阅: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("订阅请求失败: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func stripEmoji(name string) string {
	return emojiRe.ReplaceAllString(name, "")
}

func normalizeName(name string, doStripEmoji bool) string {
	name = strings.TrimSpace(name)
	if doStripEmoji {
		name = strings.TrimSpace(stripEmoji(name))
	}
	return name
}

func containsAny(s string, keywords []string) bool {
	for _, k := range keywords {
		if k != "" && strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	maps.Copy(out, m)
	return out
}

// prepareDomains 预处理域名列表：小写 + 去空白
func prepareDomains(domains []string) []string {
	var out []string
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

func parseCFReplaceRules(items []string) ([]cfReplaceRule, error) {
	var rules []cfReplaceRule
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		i := strings.Index(item, ",")
		if i < 0 {
			return nil, fmt.Errorf("cf_replace_server 格式错误: %q，需要 TYPE,payload", item)
		}
		kind := strings.ToUpper(strings.TrimSpace(item[:i]))
		payload := strings.TrimSpace(item[i+1:])
		if payload == "" {
			return nil, fmt.Errorf("cf_replace_server payload 为空: %q", item)
		}
		switch kind {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-PREFIX":
			rules = append(rules, cfReplaceRule{kind: kind, payload: strings.ToLower(payload)})
		case "DOMAIN-REGEXP":
			re, err := regexp.Compile(payload)
			if err != nil {
				return nil, fmt.Errorf("cf_replace_server 正则无效 %q: %w", payload, err)
			}
			rules = append(rules, cfReplaceRule{kind: kind, payload: payload, re: re})
		default:
			return nil, fmt.Errorf("未知 cf_replace_server 类型 %q（支持 DOMAIN / DOMAIN-SUFFIX / DOMAIN-PREFIX / DOMAIN-REGEXP）", kind)
		}
	}
	return rules, nil
}

func matchCFReplace(server string, rules []cfReplaceRule) bool {
	host := strings.TrimSpace(server)
	if host == "" {
		return false
	}
	hostLower := strings.ToLower(host)
	for _, r := range rules {
		switch r.kind {
		case "DOMAIN":
			if hostLower == r.payload {
				return true
			}
		case "DOMAIN-SUFFIX":
			if hostLower == r.payload || strings.HasSuffix(hostLower, "."+r.payload) {
				return true
			}
		case "DOMAIN-PREFIX":
			if strings.HasPrefix(hostLower, r.payload) {
				return true
			}
		case "DOMAIN-REGEXP":
			if r.re.MatchString(host) {
				return true
			}
		}
	}
	return false
}

// processSubscribedProxies 单次遍历完成关键词/类型过滤、server 替换、去 emoji，并收集节点名
func processSubscribedProxies(proxies []any, cfg *Config, rules []cfReplaceRule) (subscribedProxies []any, subscribedNames []string) {
	replace := cfg.CFIP != "" && len(rules) > 0
	for _, p := range proxies {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		name = normalizeName(name, cfg.StripEmoji)
		if containsAny(name, cfg.ExcludeKeywords) {
			continue
		}
		if typ, _ := m["type"].(string); containsAny(typ, cfg.ExcludeTypes) {
			continue
		}
		if replace {
			if server, _ := m["server"].(string); matchCFReplace(server, rules) {
				m["server"] = cfg.CFIP
			}
		}
		m["name"] = name
		subscribedNames = append(subscribedNames, name)
		subscribedProxies = append(subscribedProxies, m)
	}
	return subscribedProxies, subscribedNames
}

func processExtraProxies(cfg *Config) ([]map[string]any, []string, error) {
	out := make([]map[string]any, 0, len(cfg.ExtraProxies))
	names := make([]string, 0, len(cfg.ExtraProxies))
	for _, p := range cfg.ExtraProxies {
		m := cloneMap(p)
		if server, ok := m["server"].(string); ok && strings.TrimSpace(server) == cfIPPlaceholder {
			if cfg.CFIP == "" {
				return nil, nil, fmt.Errorf("extra_proxies 含 %s 但未配置 cf_ip", cfIPPlaceholder)
			}
			m["server"] = cfg.CFIP
		}
		name, _ := m["name"].(string)
		name = normalizeName(name, false)
		m["name"] = name
		names = append(names, name)
		out = append(out, m)
	}
	return out, names, nil
}

func containsPlaceholder(v any, ph string) bool {
	switch val := v.(type) {
	case string:
		return strings.Contains(val, ph)
	case []any:
		for _, item := range val {
			if containsPlaceholder(item, ph) {
				return true
			}
		}
	case map[string]any:
		for _, item := range val {
			if containsPlaceholder(item, ph) {
				return true
			}
		}
	}
	return false
}

func replaceListenerProxy(v any, proxy string) any {
	switch val := v.(type) {
	case string:
		return strings.ReplaceAll(val, listenerProxyPlaceholder, proxy)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = replaceListenerProxy(item, proxy)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			out[k] = replaceListenerProxy(item, proxy)
		}
		return out
	default:
		return v
	}
}

func processListeners(cfg *Config) (listeners []any, subRules any, groups []any, err error) {
	if len(cfg.Listeners) == 0 {
		return nil, nil, nil, nil
	}

	hasTemplate := len(cfg.SubRuleTemplate) > 0
	templateHasPlaceholder := hasTemplate && containsPlaceholder(cfg.SubRuleTemplate, listenerProxyPlaceholder)

	seen := make(map[string]bool, len(cfg.Listeners))
	seenGroups := make(map[string]bool)
	out := make([]any, 0, len(cfg.Listeners))
	var ruleMap map[string]any
	var ruleOrder []string
	if hasTemplate {
		ruleMap = make(map[string]any, len(cfg.Listeners))
		ruleOrder = make([]string, 0, len(cfg.Listeners))
		groups = make([]any, 0, len(cfg.Listeners))
	}

	for _, raw := range cfg.Listeners {
		m := cloneMap(raw)
		name, _ := m["name"].(string)
		name = normalizeName(name, false)
		if name == "" {
			return nil, nil, nil, fmt.Errorf("listener 缺少 name")
		}
		if seen[name] {
			return nil, nil, nil, fmt.Errorf("listener name 重复: %s", name)
		}
		seen[name] = true
		m["name"] = name

		if hasTemplate {
			proxy, _ := m["proxy"].(string)
			proxy = normalizeName(proxy, false)
			if templateHasPlaceholder && proxy == "" {
				return nil, nil, nil, fmt.Errorf("listener %s 缺少 proxy，无法展开 %s", name, listenerProxyPlaceholder)
			}
			ruleName := listenerSubRulePrefix + name
			groupName := listenerGroupPrefix + proxy
			ruleMap[ruleName] = replaceListenerProxy(cfg.SubRuleTemplate, groupName)
			ruleOrder = append(ruleOrder, ruleName)
			if proxy != "" && !seenGroups[groupName] {
				seenGroups[groupName] = true
				groups = append(groups, orderedMap{
					m: map[string]any{
						"name":    groupName,
						"type":    "select",
						"hidden":  true,
						"proxies": []any{proxy},
					},
					prependKeys: []string{"name", "type", "hidden"},
					appendKeys:  []string{"proxies"},
				})
			}
			delete(m, "proxy")
			m["rule"] = ruleName
		}

		out = append(out, orderedMap{m: m, prependKeys: listenerOrder})
	}

	if hasTemplate {
		return out, orderedMap{m: ruleMap, prependKeys: ruleOrder}, groups, nil
	}
	return out, nil, nil, nil
}

// expandNamePlaceholders 递归把整项等于节点名占位符的值替换为节点名列表
func expandNamePlaceholders(v any, replacements map[string][]string) any {
	switch val := v.(type) {
	case string:
		if names, ok := replacements[val]; ok {
			return names
		}
		return val
	case []any:
		out := make([]any, 0, len(val))
		for _, item := range val {
			expanded := expandNamePlaceholders(item, replacements)
			if names, ok := expanded.([]string); ok {
				for _, n := range names {
					out = append(out, n)
				}
			} else {
				out = append(out, expanded)
			}
		}
		return out
	case map[string]any:
		for k, item := range val {
			val[k] = expandNamePlaceholders(item, replacements)
		}
		return val
	default:
		return v
	}
}

// toAnySlice 把展开后的值统一转成 []any
func toAnySlice(v any) []any {
	switch val := v.(type) {
	case []any:
		return val
	case []string:
		out := make([]any, len(val))
		for i, s := range val {
			out[i] = s
		}
		return out
	case string:
		return []any{val}
	default:
		return nil
	}
}

// mergeHosts 合并 CF 生成和 inject 的 hosts，inject 优先
func mergeHosts(cfHosts map[string]any, injectHosts any) map[string]any {
	out := make(map[string]any)
	maps.Copy(out, cfHosts)
	if ih, ok := injectHosts.(map[string]any); ok {
		maps.Copy(out, ih)
	}
	return out
}

func buildCFHosts(ip string, domains []string) map[string]any {
	out := make(map[string]any)
	for _, d := range domains {
		out[d] = ip
		out["*."+d] = ip
	}
	return out
}

func buildCFRules(domains []string) []any {
	rules := make([]any, 0, len(domains))
	for _, d := range domains {
		rules = append(rules, "DOMAIN-SUFFIX,"+d+",DIRECT")
	}
	return rules
}

// proxyOrder 控制节点字段输出顺序：name, type, server, port，其余按字母序
var proxyOrder = []string{"name", "type", "server", "port"}

var listenerOrder = []string{"name", "type", "port", "listen", "rule", "proxy"}

// orderedMap 按指定顺序输出字段：prependKeys 最先，appendKeys 最后，其余按字母序
type orderedMap struct {
	m           map[string]any
	prependKeys []string
	appendKeys  []string
}

func (o orderedMap) MarshalYAML() (any, error) {
	node := &yaml.Node{Kind: yaml.MappingNode}
	emitted := make(map[string]bool)
	appendSet := make(map[string]bool)
	for _, k := range o.appendKeys {
		appendSet[k] = true
	}
	for _, k := range o.prependKeys {
		if v, ok := o.m[k]; ok {
			valNode := &yaml.Node{}
			if err := valNode.Encode(v); err != nil {
				return nil, err
			}
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, valNode)
			emitted[k] = true
		}
	}
	var rest []string
	for k := range o.m {
		if !emitted[k] && !appendSet[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		valNode := &yaml.Node{}
		if err := valNode.Encode(o.m[k]); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, valNode)
	}
	for _, k := range o.appendKeys {
		if v, ok := o.m[k]; ok {
			valNode := &yaml.Node{}
			if err := valNode.Encode(v); err != nil {
				return nil, err
			}
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, valNode)
		}
	}
	return node, nil
}

// marshalOutput 用 2 空格缩进序列化,去掉 yaml.Encoder 的文档头
func marshalOutput(output map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(output); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return bytes.TrimPrefix(buf.Bytes(), []byte("---\n")), nil
}

func main() {
	configPath := cmp.Or(os.Getenv("CONFIG_PATH"), "config.yaml")
	cfg, err := loadConfig(configPath)
	if err != nil {
		fatal(err)
	}

	cfReplaceRules, err := parseCFReplaceRules(cfg.CFReplaceServer)
	if err != nil {
		fatal(err)
	}

	headers := canonicalizeHeaders(cfg.Headers)
	if _, ok := headers["User-Agent"]; !ok {
		headers["User-Agent"] = "clash-verge/v1.0"
	}
	client := &http.Client{
		Transport: &headerTransport{
			rt: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
			},
			headers: headers,
		},
	}

	body, err := fetchSub(client, cfg.SubURL)
	if err != nil {
		fatal(err)
	}

	var sub map[string]any
	if err := yaml.Unmarshal(body, &sub); err != nil {
		fatal(fmt.Errorf("解析订阅: %w", err))
	}

	rawProxies, _ := sub["proxies"].([]any)
	subscribedProxies, subscribedNames := processSubscribedProxies(rawProxies, cfg, cfReplaceRules)

	extraProxies, extraNames, err := processExtraProxies(cfg)
	if err != nil {
		fatal(err)
	}

	output := make(map[string]any)
	proxies := make([]any, 0, len(extraProxies)+len(subscribedProxies))
	for _, p := range extraProxies {
		proxies = append(proxies, orderedMap{m: p, prependKeys: proxyOrder})
	}
	for _, p := range subscribedProxies {
		if m, ok := p.(map[string]any); ok {
			proxies = append(proxies, orderedMap{m: m, prependKeys: proxyOrder})
		}
	}
	output["proxies"] = proxies

	replacements := map[string][]string{
		subscribedPlaceholder: subscribedNames,
		extraPlaceholder:      extraNames,
	}

	// inject 全部键（含 hosts/rules），先原样输出并展开占位符；proxy-groups 里 proxies 放最后
	for k, v := range cfg.Inject {
		if k == "listeners" || k == "sub-rules" {
			fatal(fmt.Errorf("inject 不能包含 %s，请使用顶层 listeners / sub_rule_template", k))
		}
		if k == "proxy-groups" {
			if groups, ok := v.([]any); ok {
				expanded := expandNamePlaceholders(groups, replacements).([]any)
				out := make([]any, 0, len(expanded))
				for _, g := range expanded {
					if gm, ok := g.(map[string]any); ok {
						out = append(out, orderedMap{m: gm, appendKeys: []string{"proxies"}})
					} else {
						out = append(out, g)
					}
				}
				output[k] = out
				continue
			}
		}
		output[k] = expandNamePlaceholders(v, replacements)
	}

	listeners, subRules, listenerGroups, err := processListeners(cfg)
	if err != nil {
		fatal(err)
	}
	if listeners != nil {
		output["listeners"] = listeners
	}
	if subRules != nil {
		output["sub-rules"] = subRules
	}
	if len(listenerGroups) > 0 {
		output["proxy-groups"] = append(toAnySlice(output["proxy-groups"]), listenerGroups...)
	}

	// CF hosts 重写：hosts 与 inject 合并（inject 优先），CF 规则置顶
	if cfg.CFIP != "" && len(cfg.CFDomains) > 0 {
		cfDomains := prepareDomains(cfg.CFDomains)
		output["hosts"] = mergeHosts(buildCFHosts(cfg.CFIP, cfDomains), output["hosts"])
		rules := buildCFRules(cfDomains)
		rules = append(rules, toAnySlice(output["rules"])...)
		output["rules"] = rules
	}

	out, err := marshalOutput(output)
	if err != nil {
		fatal(fmt.Errorf("序列化输出: %w", err))
	}

	if cfg.Output != "" {
		if err := os.WriteFile(cfg.Output, out, 0o644); err != nil {
			fatal(fmt.Errorf("写入输出文件: %w", err))
		}
		fmt.Println("已写入", cfg.Output)
	} else {
		fmt.Print(string(out))
	}
}
