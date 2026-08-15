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

const placeholder = "__SUBSCRIBED__"

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
}

type headerTransport struct {
	rt      http.RoundTripper
	headers map[string]string
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
	return strings.TrimSpace(emojiRe.ReplaceAllString(name, ""))
}

func containsAny(s string, keywords []string) bool {
	for _, k := range keywords {
		if k != "" && strings.Contains(s, k) {
			return true
		}
	}
	return false
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

func matchesDomains(host string, domains []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// processProxies 单次遍历完成关键词/类型过滤、server 替换、去 emoji，并收集节点名
func processProxies(proxies []any, cfg *Config) (filtered []any, nodeNames []string) {
	replaceDomains := prepareDomains(cfg.CFReplaceServer)
	for _, p := range proxies {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		if containsAny(name, cfg.ExcludeKeywords) {
			continue
		}
		if typ, _ := m["type"].(string); containsAny(typ, cfg.ExcludeTypes) {
			continue
		}
		if cfg.CFIP != "" {
			if server, _ := m["server"].(string); matchesDomains(server, replaceDomains) {
				m["server"] = cfg.CFIP
			}
		}
		if cfg.StripEmoji {
			name = stripEmoji(name)
			m["name"] = name
		}
		nodeNames = append(nodeNames, name)
		filtered = append(filtered, m)
	}
	return filtered, nodeNames
}

// expandPlaceholder 递归把值中的占位符替换为节点名列表
func expandPlaceholder(v any, nodeNames []string) any {
	switch val := v.(type) {
	case string:
		if val == placeholder {
			return nodeNames
		}
		return val
	case []any:
		out := make([]any, 0, len(val))
		for _, item := range val {
			expanded := expandPlaceholder(item, nodeNames)
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
			val[k] = expandPlaceholder(item, nodeNames)
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
	filtered, nodeNames := processProxies(rawProxies, cfg)

	output := make(map[string]any)
	proxies := make([]any, 0, len(cfg.ExtraProxies)+len(filtered))
	for _, p := range cfg.ExtraProxies {
		proxies = append(proxies, orderedMap{m: p, prependKeys: proxyOrder})
	}
	for _, p := range filtered {
		if m, ok := p.(map[string]any); ok {
			proxies = append(proxies, orderedMap{m: m, prependKeys: proxyOrder})
		}
	}
	output["proxies"] = proxies

	// inject 全部键（含 hosts/rules），先原样输出并展开占位符；proxy-groups 里 proxies 放最后
	for k, v := range cfg.Inject {
		if k == "proxy-groups" {
			if groups, ok := v.([]any); ok {
				expanded := expandPlaceholder(groups, nodeNames).([]any)
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
		output[k] = expandPlaceholder(v, nodeNames)
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
