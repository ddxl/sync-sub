# sync-sub

mihomo 订阅处理工具：拉取订阅，按需过滤、清洗节点，注入自定义配置后输出。

## 用法

```sh
sync-sub
```

默认读取当前目录下的 `config.yaml`，也可通过 `CONFIG_PATH` 环境变量指定配置文件：

```sh
CONFIG_PATH=/path/to/config.yaml sync-sub
```

环境变量：

| 变量          | 说明         | 默认值        |
| ------------- | ------------ | ------------- |
| `CONFIG_PATH` | 配置文件路径 | `config.yaml` |

HTTP 代理遵循 `HTTP_PROXY` / `HTTPS_PROXY` 等标准环境变量。

## 构建

禁用 CGO、裁剪调试信息，输出不带路径信息的精简二进制。以下为各平台本地构建命令。

macOS / Linux（amd64 / arm64）：

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sync-sub .
```

Windows（amd64，PowerShell）：

```powershell
$env:CGO_ENABLED=0; go build -trimpath -ldflags "-s -w" -o sync-sub.exe .
```

## 配置

```yaml
sub_url: "https://example.com/sub?token=xxx" # mihomo 订阅地址
output: "out.yaml" # 可选；不设置则输出到 stdout
headers: # 可选；请求订阅时附加的自定义请求头，未配置 User-Agent 时默认 clash-verge/v1.0
  User-Agent: "clash-verge/v1.0"
cf_ip: "104.16.0.1" # 可选；CF 优选 IP，供 cf_replace_server、extra_proxies 的 __CF_IP__、cf_domains 共用
exclude_keywords: # 可选；代理名含任一关键词即剔除
  - "剩余"
  - "到期"
exclude_types: # 可选；type 命中任一即剔除
  - "ss"
strip_emoji: false # 可选；true 时从订阅节点名中删除 emoji（不替换成文字），默认 false
extra_proxies: # 可选；自定义代理，放在输出 proxies 最上方；server 为 __CF_IP__ 时替换为 cf_ip
  - name: "香港CF"
    type: vless
    server: "__CF_IP__"
    port: 443
cf_replace_server: # 可选；订阅节点 server 命中任一规则即替换为 cf_ip；写法同 mihomo 规则类型
  - "DOMAIN,cdn.example.com"
  - "DOMAIN-SUFFIX,pages.dev"
  - "DOMAIN-PREFIX,cf-"
  - "DOMAIN-REGEXP,(?i)^.+\\.workers\\.dev$"
cf_domains: # 可选；生成 hosts 条目和 DIRECT 直连规则的域名
  - "cloudflare.com"
sub_rule_template: # 可选；与 listeners 一起使用；按每个 listener 克隆一份 sub-rules
  - "GEOIP,CN,DIRECT"
  - "GEOSITE,CN,DIRECT"
  - "MATCH,__LISTENER_PROXY__"
listeners: # 可选；有模板时展开 sub-rules，并生成隐藏策略组作为 MATCH 兜底
  - name: mixed-hk
    type: mixed
    port: 7890
    proxy: 香港CF
  - name: mixed-us
    type: mixed
    port: 7891
    proxy: 美国CF
inject: # 可选；注入任意顶层键；不可包含 listeners / sub-rules
  rules:
    - "MATCH,节点选择"
  proxy-groups:
    - name: "节点选择"
      type: select
      proxies:
        - "__EXTRA__" # 展开为 extra_proxies 的节点名列表
        - "__SUBSCRIBED__" # 展开为订阅过滤后的节点名列表
        - "DIRECT"
```

## 功能

- **过滤节点**：`exclude_keywords` 中任一关键词命中代理名即剔除该节点；不配置则不过滤。
- **过滤类型**：`exclude_types` 中任一 type 命中即剔除该节点；不配置则不过滤。
- **名字规范化**：所有节点名、listener 名都会去掉首尾空白。`strip_emoji: true` 时先删除订阅节点名中的 emoji，再去一次空白；emoji 只删除、不替换成文字。`extra_proxies` 和 listener 的名字不去 emoji。
- **server 替换**：`cf_replace_server` 每条必须是 `TYPE,payload`，命中订阅节点的 `server` 时替换为 `cf_ip`（只改 `server`，不动 `sni` / `servername` / `host`）。多条之间为或。支持：
  - `DOMAIN,example.com`：整体相等（忽略大小写）
  - `DOMAIN-SUFFIX,example.com`：等于该域名或其子域
  - `DOMAIN-PREFIX,cdn.`：前缀匹配（忽略大小写，不自动补 `.`）
  - `DOMAIN-REGEXP,^cf[-.].+$`：对原始 `server` 做正则匹配；需要忽略大小写时自己写 `(?i)`
- **自定义节点**：`extra_proxies` 追加的节点放在所有节点最上方，不走关键词/类型过滤和 `cf_replace_server`。`server` 去掉首尾空白后若等于 `__CF_IP__`，则整项替换为 `cf_ip`；其它字段（如 `sni`）不动。未配置 `cf_ip` 却使用该占位符会报错。
- **占位符**：
  - `__SUBSCRIBED__`：inject 中整项替换为订阅过滤后的节点名列表（不含 extra）
  - `__EXTRA__`：inject 中整项替换为 `extra_proxies` 的节点名列表（声明顺序）
  - `__CF_IP__`：仅用于 extra 的 `server`，见上
  - `__LISTENER_PROXY__`：仅用于 `sub_rule_template`，替换为该 listener 对应的隐藏策略组名
- **listeners / sub-rules**：`sub_rule_template` 与 `listeners` 都是顶层配置，不要写进 inject。两者都配置时，按每个 listener 克隆一份模板：
  - listener 的 `rule` 和 sub-rule 的 key 都是 `sub-rule-<listener.name>`
  - 输出的 listener 去掉 `proxy`
  - 为每个用到的节点生成隐藏策略组 `hidden-proxy-<节点名>`（`type: select`、`hidden: true`、组内只有该节点），多个 listener 共用同一节点时只生成一份
  - 模板里的 `__LISTENER_PROXY__` 展开为这个组名，供 `MATCH` 兜底；mihomo 的 MATCH 指向策略组，而不是节点名
  - 组带 `hidden: true`，面板里不会显示，inject 里自己写的组不受影响
  - 只配 listeners、不配模板时原样输出 listeners（保留 `proxy`），不生成 `sub-rules` 和隐藏组
  - 只配模板、不配 listeners 时不展开
  - 模板含占位符但 listener 缺少 `proxy`、或 name 为空/重复时直接报错
  - `listeners[].proxy` 必须和 `proxies` 里的节点名完全一致
- **CF 域名 hosts 重写**：为 `cf_domains` 中每个域名生成裸域名和 `*.域名` 两条 hosts 条目，并在 `rules` 最上方生成 `DOMAIN-SUFFIX,域名,DIRECT` 直连规则。`inject.hosts` 中同名的条目优先。
- **输出**：`output` 指定写入的文件，否则打印到 stdout。只输出 `proxies`、`inject` 中定义的键，以及展开后的 `listeners` / `sub-rules` / 隐藏策略组。
