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
cf_ip: "104.16.0.1" # 可选；CF 优选 IP，cf_replace_server 和 cf_domains 共用
exclude_keywords: # 可选；代理名含任一关键词即剔除
  - "剩余"
  - "到期"
exclude_types: # 可选；type 命中任一即剔除
  - "ss"
strip_emoji: false # 可选；true 时移除节点名中的 emoji 图标，默认 false
extra_proxies: # 可选；自定义代理，放在输出 proxies 最上方
  - name: "my-proxy"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "secret"
cf_replace_server: # 可选；server 命中任一域名（含子域）即替换为 cf_ip
  - "cf-node.example.com"
cf_domains: # 可选；生成 hosts 条目和 DIRECT 直连规则的域名
  - "cloudflare.com"
inject: # 可选；注入任意顶层键，覆盖订阅同名键
  rules:
    - "MATCH,🚀 节点选择"
  proxy-groups:
    - name: "🚀 节点选择"
      type: select
      proxies:
        - "__SUBSCRIBED__" # 展开为订阅过滤后的节点名列表
        - "DIRECT"
```

## 功能

- **过滤节点**：`exclude_keywords` 中任一关键词命中代理名即剔除该节点；不配置则不过滤。
- **过滤类型**：`exclude_types` 中任一 type 命中即剔除该节点；不配置则不过滤。
- **server 替换**：`cf_replace_server` 中节点 `server` 命中任一域名（含子域）时替换为 `cf_ip`（仅替换 `server` 字段，不动 `servername`）。
- **去 emoji**：`strip_emoji: true` 时移除节点名中的 emoji 图标（纯 unicode 处理，无第三方依赖），默认不去除。
- **自定义节点**：`extra_proxies` 追加的节点放在所有节点最上方。
- **占位符**：inject 内容里的 `__SUBSCRIBED__` 会被替换为订阅过滤后节点名列表（不含 `extra_proxies`），常用于 proxy-groups 自动引用全部节点。
- **CF 域名 hosts 重写**：为 `cf_domains` 中每个域名生成裸域名和 `*.域名` 两条 hosts 条目，并在 `rules` 最上方生成 `DOMAIN-SUFFIX,域名,DIRECT` 直连规则。`inject.hosts` 中同名的条目优先。
- **输出**：`output` 指定写入的文件，否则打印到 stdout。只输出 `proxies` 和 `inject` 中定义的键。
