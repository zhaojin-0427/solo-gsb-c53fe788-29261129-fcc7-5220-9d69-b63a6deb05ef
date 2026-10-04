# 可靠 Webhook 投递服务

基于 **Python 3.12 + FastAPI + PostgreSQL + S3 兼容对象存储（本地一键用 MinIO）**
的可靠 Webhook 投递系统，使用 **Docker Compose** 一键启动。

能力：

- **事件载荷内容寻址 + 对象存储去重**：事件载荷以规范化 JSON（键排序、无空白）
  的 **SHA-256** 作为对象键存入 S3 兼容对象存储，对象不可变、同内容全局去重；
  PostgreSQL 只保存对象元数据（摘要、大小、引用计数），事件仅以摘要引用对象。
  提交由**持久化状态机**协调“对象上传”与“数据库事务”，任一步失败或进程重启
  都不会产生可见半成品、悬空引用或重复投递。Worker 取载荷时**先复核摘要再
  HMAC 签名**。旧 JSONB 数据支持**可断点续跑的在线迁移与双读**，并提供带
  **引用复核 + 宽限期**的幂等垃圾回收（GC）。详见下文
  [“事件载荷对象存储（内容寻址/去重/迁移/回收）”](#事件载荷对象存储内容寻址去重迁移回收)。
- **事件幂等提交**：生产者以 `(source, event_id)` 提交事件；重复提交返回原事件
  （HTTP 200，响应体 `duplicate: true`），**不新增任何投递**。
- **订阅配置版本化 + 无损切换**：`target_url`、HMAC 密钥与重试参数保存为不可变版本
  （revision 从 1 单调递增）。发布新版本必须携带 `expected_revision` 做 CAS；
  切换边界与发布事务原子确定——边界前创建的投递及其后续重试/接管始终用旧版本，
  边界后的投递用新版本；并发发布只有一个成功。详见下文[“配置版本与无损切换”](#配置版本与无损切换)。
- **严格顺序投递**：同一订阅（source → target）严格按事件顺序处理——前一事件
  成功或进入死信之前，后一事件不会被发送。
- **租约抢占与接管**：Worker 从数据库认领任务并持有租约；Worker 宕机/卡死导致
  租约过期后，其他 Worker 可接管。回写带租约令牌栅栏，过期结果会被丢弃
  （at-least-once 语义，极端接管场景下目标端可能收到一次重复投递）。
- **HMAC 签名**：每次投递携带时间戳签名头
  `X-Webhook-Signature: t=<unix秒>,v1=<HMAC-SHA256 hex>`，签名内容为
  `<timestamp>.<紧凑排序 JSON 载荷>`；密钥取自该投递钉住的配置版本。
- **指数退避 + 死信**：失败按 `base * 2^(n-1)` 退避（封顶），重试次数与退避参数
  均取自投递版本（默认最多 6 次尝试），满后进入死信队列。
- **投递历史 / 死信重放**：可查询投递与每次尝试明细；重放会在同一投递链
  （`chain_id`）上**新建投递记录**（`chain_seq + 1`），旧记录完整保留。
  重放默认沿用原版本，也可显式选用当前版本。
- **出站目标安全策略（SSRF 防护）**：创建订阅/发布版本时仅接受 `http/https`、
  拒绝带用户信息的 URL，并校验主机解析出的**全部**地址；默认阻止回环、链路本地、
  私网、组播、保留/未指定及云元数据地址。Worker 每次尝试重新解析并把本次允许
  的地址**固定到实际连接**（保持原 `Host` 头与 HTTPS SNI），防校验后 DNS
  重绑定；重定向每一跳都按同一规则校验。详见下文
  [“出站目标安全策略”](#出站目标安全策略ssrf-防护)。
- **订阅密钥信封加密 + 在线主密钥轮换**：保存配置版本时为每条密钥生成随机
  DEK，用 AES-256-GCM 加密（AAD 绑定 `subscription_id` + `version_id`），
  DEK 再由本地密钥环的主密钥包裹；数据库只存密文，API/查询/日志不暴露明文，
  Worker 仅在签名前解密。旧明文记录可幂等、断点续跑地批量迁移，迁移期间新旧
  格式均可投递；轮换只重包裹 DEK，进度持久化、可失败恢复、可并发执行；尚有
  记录引用旧 `key_id` 时禁止移除旧密钥。详见下文
  [“订阅密钥信封加密与主密钥轮换”](#订阅密钥信封加密与主密钥轮换)。
- **本地回调接收器**：内置带签名校验、成功/失败/前 N 次失败/慢响应/重定向等
  端点的 Receiver，便于本地联调与演示。

## 架构

| 服务 | 端口（宿主机） | 说明 |
| --- | --- | --- |
| `db` | 5432 | PostgreSQL 16，数据卷 `pgdata` 持久化 |
| `minio` | 9000 / 9001 | S3 兼容对象存储（9000 为 S3 API，9001 为 Web 控制台），数据卷 `miniodata` |
| `api` | 8000 | FastAPI：提交事件、订阅管理、历史/死信/重放 API；含提交状态机后台恢复 |
| `worker` | — | 投递进程，靠数据库行锁认领任务，可水平扩展；取载荷时复核摘要再签名 |
| `receiver` | 8001 | 本地回调接收器（开发/联调用） |

MinIO 控制台：<http://localhost:9001>（默认凭据 `minioadmin / minioadmin`），
可在 `webhook-payloads` 桶里直接浏览以 SHA-256 命名的不可变载荷对象。

载荷对象存储桶在 api/worker 启动时**自动创建**，无需手工建桶。

密钥管理命令（明文迁移、主密钥轮换、移除旧密钥、状态查看）以一次性容器运行：
`docker compose run --rm api python -m app.keyadmin <子命令>`，详见
[“订阅密钥信封加密与主密钥轮换”](#订阅密钥信封加密与主密钥轮换)。

载荷对象管理命令（旧 JSONB 在线迁移、垃圾回收、崩溃恢复、状态查看）：
`docker compose run --rm api python -m app.payloadadmin <子命令>`，详见
[“事件载荷对象存储（内容寻址/去重/迁移/回收）”](#事件载荷对象存储内容寻址去重迁移回收)。

投递顺序与租约在数据库层实现（核心见 `app/repository.py`）：

1. 每个订阅的投递有一个全局单调的 `seq`；Worker 只认领该订阅 **seq 最小且未终结
   且前面不存在 pending/in_flight 投递** 的任务（`FOR UPDATE SKIP LOCKED`），
   多 Worker 并发不会重复认领。
2. 认领后状态为 `in_flight`，设置 `leased_by`（租约令牌）与
   `lease_expires_at = now() + LEASE_SECONDS`。
3. 投递完成后，记录尝试与结算都以租约令牌为条件；租约已被接管时本次结果作废。
4. 成功 → `succeeded`；失败且未满 6 次 → 回到 `pending` 并设置指数退避时间
   `not_before`；满 6 次 → `dead_lettered`，其后同订阅的下一事件才允许发送。

> 生产配置要求 `LEASE_SECONDS`（默认 30）大于 `HTTP_TIMEOUT_SECONDS`（默认 10），
> 因此存活 Worker 不会在请求飞行中失去租约；接管只针对真正僵死的 Worker。

## 快速开始

```bash
docker compose up --build
```

启动后：

- API 文档（Swagger UI）：<http://localhost:8000/docs>
- API OpenAPI：<http://localhost:8000/openapi.json>
- API 健康检查：<http://localhost:8000/health>
- 回调接收器：<http://localhost:8001/> （查看记录：<http://localhost:8001/received>）

扩容 Worker（严格顺序仍然成立，只是不同订阅可并行）：

```bash
docker compose up --scale worker=3
```

> 订阅目标受出站安全策略保护：默认只允许公网 `http/https`，Compose 内的
> `receiver` 已默认放行，故上面的体验流程可直接运行。访问内网/回环目标或
> 调整放行主机/CIDR 见 [“出站目标安全策略”](#出站目标安全策略ssrf-防护)。

### 30 秒体验流程

```bash
# 1) 注册订阅：source=orders 的事件投递到本地接收器
curl -s -X POST localhost:8000/api/v1/subscriptions \
  -H 'Content-Type: application/json' \
  -d '{"source":"orders",
       "target_url":"http://receiver:8001/receive",
       "secret":"dev-signing-secret"}'

# 2) 提交事件（首次 201）
curl -i -X POST localhost:8000/api/v1/events \
  -H 'Content-Type: application/json' \
  -d '{"source":"orders","event_id":"evt-1001","payload":{"order":42}}'

# 3) 再次提交同一事件 -> 200，duplicate=true，不新增投递
curl -i -X POST localhost:8000/api/v1/events \
  -H 'Content-Type: application/json' \
  -d '{"source":"orders","event_id":"evt-1001","payload":{"order":42}}'

# 4) 查看投递历史与每次尝试明细
curl -s 'localhost:8000/api/v1/deliveries?source=orders' | python3 -m json.tool
#   取返回中的 id：
curl -s localhost:8000/api/v1/deliveries/1/attempts | python3 -m json.tool

# 5) 查看接收器实际收到的内容（含签名校验结果）
curl -s localhost:8001/received | python3 -m json.tool

# 6) 查看事件载荷的内容地址（payload_digest 即规范化 JSON 的 SHA-256）
#    与对象存储去重/迁移/GC 状态（对象本体在 MinIO 的 webhook-payloads 桶中）
curl -s localhost:8000/api/v1/payloads/status | python3 -m json.tool
# 垃圾回收状态（候选/到期数、最近一轮 GC 运行；物理回收见下文管理命令）
curl -s localhost:8000/api/v1/payloads/gc | python3 -m json.tool
# 也可在 MinIO 控制台 http://localhost:9001 浏览 webhook-payloads 桶（minioadmin/minioadmin）
```

### 失败退避与死信重放

```bash
# /fail 始终返回 500
curl -s -X POST localhost:8000/api/v1/subscriptions \
  -H 'Content-Type: application/json' \
  -d '{"source":"billing",
       "target_url":"http://receiver:8001/fail",
       "secret":"dev-signing-secret"}'

curl -s -X POST localhost:8000/api/v1/events \
  -H 'Content-Type: application/json' \
  -d '{"source":"billing","event_id":"bill-1","payload":{}}'

# 等待 6 次尝试（默认退避 5,10,20,40,80 秒，约 2.5 分钟）
curl -s 'localhost:8000/api/v1/dead-letters?source=billing' | python3 -m json.tool

# 让接收器不再失败，然后重放（返回 201，新投递属于同一 chain_id，chain_seq=2）
curl -s -X POST 'localhost:8001/control/fail?enabled=false'
curl -i -X POST localhost:8000/api/v1/dead-letters/<delivery_id>/replay
```

也可把目标设为 `http://receiver:8001/fail/2`：对同一投递前 2 次返回 500、
第 3 次返回 200，可快速观察退避后重试成功。

## API 一览

所有业务 API 前缀为 `/api/v1`，交互文档见 `/docs`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/events` | 提交/幂等提交事件；首次 201，重复 200 |
| GET | `/events/{id}` | 查询事件 |
| GET | `/events/{id}/deliveries` | 事件对应的所有投递 |
| POST | `/subscriptions` | 注册订阅（同 source+URL 重复注册为重新激活；同时生成 revision=1） |
| GET | `/subscriptions?source=` | 列出订阅（含 `current_revision`，不含密钥） |
| GET | `/subscriptions/{id}` | 查询订阅（含 `current_revision`，不含密钥） |
| POST | `/subscriptions/{id}/versions` | 发布新配置版本（CAS，必须带 `expected_revision`；201/409） |
| GET | `/subscriptions/{id}/versions` | 列出全部配置版本与切换边界（不含密钥） |
| GET | `/deliveries?status=&subscription_id=&source=&config_revision=` | 投递历史（含实际版本与边界） |
| GET | `/deliveries/{id}` | 投递详情（含 `config_revision`、`config_effective_at`） |
| GET | `/deliveries/{id}/attempts` | 每次尝试明细（状态码、响应摘要、错误、租约时间） |
| GET | `/dead-letters?subscription_id=&source=` | 死信列表 |
| POST | `/dead-letters/{id}/replay` | 死信重放（201；非死信 409；链上有未完成投递 409） |
| GET | `/crypto/status` | 密钥环/迁移/轮换状态（只含 key_id，不含密钥材料） |
| GET | `/payloads/status` | 载荷对象存储/去重/在线迁移/GC 状态（只含计数，不含载荷内容） |
| GET | `/payloads/gc` | 垃圾回收总览（候选/到期数、宽限、最近运行；只读） |
| GET | `/payloads/gc/{digest}` | 单个对象摘要的回收状态（候选/到期时刻/引用计数/进行中提交；只读） |
| GET | `/health` | 健康检查 |

投递状态：`pending`（等待/退避中）、`in_flight`（已被 Worker 认领）、
`succeeded`、`dead_lettered`。

尝试结果（`outcome`）：`success`、`http_error`、`network_error`、`timeout`、
`security_blocked`（出站安全策略拒绝）、`crypto_error`（订阅密钥不可用）、
`payload_integrity`（载荷对象缺失/摘要复核失败/非合法 JSON，拒绝签名）。

## 配置版本与无损切换

每个订阅拥有一串**不可变**配置版本（`subscription_versions`）：

- 版本内容：`target_url`、HMAC `secret`（以信封加密形式落库，见
  [“订阅密钥信封加密与主密钥轮换”](#订阅密钥信封加密与主密钥轮换)）、
  `max_attempts`、`backoff_base_seconds`、`backoff_cap_seconds`；
- `revision` 从 1 开始单调递增；旧版本永不被修改/删除；
- 每条投递（`deliveries.config_version_id`）在**创建的那一刻**固化所用版本。

### 切换边界如何确定（原子性）

- 发布新版本与事件提交都在**单数据库事务**内完成，且事件提交事务会先对该
  source 的活跃订阅行加 `FOR UPDATE` 行锁，与发布事务互斥；
- 因此每个与发布竞争的事件事务，其归属由“谁先拿到订阅行锁/先提交”唯一决定，
  边界前后泾渭分明，不存在跨界投递；
- 并发发布同一 `expected_revision`：只有一个 `201`，其余 `409`
  （`detail.code = revision_conflict`）。

### 版本对投递的影响（钉死语义）

- **边界前**已创建的投递（含其全部后续重试、租约接管后的再投递）始终使用旧版本的
  URL、密钥、`max_attempts` 与退避参数；
- **边界后**创建的投递使用新版本；
- Worker 每次执行都通过投递记录 JOIN 其版本读取 URL/密钥/重试参数，
  重试时不会“顺手”改用当前版本；
- 投递请求额外携带 `X-Webhook-Config-Revision: <revision>` 头，便于回调端识别。

### 发布新版本

```bash
# 先取当前 revision
curl -s localhost:8000/api/v1/subscriptions/1/versions

# 发布（expected_revision 必须等于当前 revision；重试参数缺省继承当前版本）
curl -i -X POST localhost:8000/api/v1/subscriptions/1/versions \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"http://receiver:8001/receive",
       "secret":"new-signing-secret",
       "expected_revision":1,
       "max_attempts":6,
       "backoff_base_seconds":5,
       "backoff_cap_seconds":300}'
# 201 -> revision=2 生效；若期间别人已发布 -> 409 revision_conflict
```

版本查询返回（**不含 secret**，仅含包裹密钥的 `secret_key_id` 标识）：

```json
[
  {"version_id": 1, "subscription_id": 1, "revision": 1,
   "target_url": "http://receiver:8001/receive",
   "max_attempts": 6, "backoff_base_seconds": 5.0, "backoff_cap_seconds": 300.0,
   "secret_key_id": "dev-k1",
   "created_at": "…", "superseded_at": "…", "is_current": false},
  {"version_id": 2, "subscription_id": 1, "revision": 2,
   "target_url": "http://receiver:8001/receive",
   "max_attempts": 6, "backoff_base_seconds": 5.0, "backoff_cap_seconds": 300.0,
   "secret_key_id": "dev-k1",
   "created_at": "…", "superseded_at": null, "is_current": true}
]
```

`created_at` 是该版本成为当前版本的时刻（切换边界起点），`superseded_at` 是它
被下一版本取代的时刻（当前版本为 `null`）。投递详情中的 `config_revision` 与
`config_effective_at`（即该版本的 `created_at`）说明该投递实际使用的版本与边界；
也可用 `/deliveries?config_revision=1` 按版本筛选。

### 死信重放的版本选择

```bash
# 默认：新投递沿用原死信投递的版本（config_revision 不变）
curl -i -X POST localhost:8000/api/v1/dead-letters/7/replay

# 显式选用订阅当前版本
curl -i -X POST localhost:8000/api/v1/dead-letters/7/replay \
  -H 'Content-Type: application/json' -d '{"use_current_version":true}'
```

两种选择都随**新投递记录**固化（`config_version_id` 外键），之后该新记录的重试
同样钉死所选版本。响应中 `config_revision` 即固化结果。

### 注册时指定初始版本重试参数

```bash
curl -s -X POST localhost:8000/api/v1/subscriptions \
  -H 'Content-Type: application/json' \
  -d '{"source":"orders",
       "target_url":"http://receiver:8001/receive",
       "secret":"dev-signing-secret",
       "max_attempts":4,
       "backoff_base_seconds":2,
       "backoff_cap_seconds":60}'
```

三个重试参数均可省略，省略时 revision=1 使用服务端全局默认（`MAX_ATTEMPTS` 等）。

### 投递请求格式（Worker → 你的回调）


```
POST <target_url> HTTP/1.1
Content-Type: application/json
X-Webhook-Signature: t=1758000000,v1=ab12...
X-Webhook-Event: orders
X-Webhook-Event-Id: evt-1001
X-Webhook-Delivery-Id: 7
X-Webhook-Attempt: 1
X-Webhook-Config-Revision: 2
```

- 载荷为紧凑 JSON（键排序、无空白），签名原文 `"<t>.<载荷>"`，HMAC-SHA256
  使用**该投递钉住版本**的订阅密钥。只有响应 **2xx** 视为成功；连接错误、超时、
  非 2xx 均计为一次失败。
- 各语言验签示例（Python）：

```python
import hmac, hashlib, json
expected = hmac.new(
    secret.encode(),
    f"{timestamp}.{json.dumps(body, sort_keys=True, separators=(',', ':'))}".encode(),
    hashlib.sha256,
).hexdigest()
hmac.compare_digest(expected, signature_v1)
```

## 事件载荷对象存储（内容寻址/去重/迁移/回收）

事件载荷不再直接保存在 `events.payload`（该 JSONB 列仅承载升级前的旧数据），
而是存到 **S3 兼容对象存储**，数据库只保留元数据与引用：

```
提交事件 payload（JSON 对象）
   │ 规范化：json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=False)
   ▼
规范化字节 bytes ── SHA-256 ──▶ digest（64 位 hex，即对象键）
   │                                     │
   ▼                                     ▼
对象存储 PUT s3://<bucket>/<digest>   event_payload_objects(digest, size, ref_count)
   （不可变、同键同内容、天然去重）      events.payload_digest ──引用──▶ digest
```

- 规范化规则与 HMAC 签名所用“紧凑排序 JSON”**完全一致**，因此“取对象→复核→
  签名”的签名结果与重构前逐字节相同，幂等、顺序、版本固定等语义不受影响；
- 多个事件（甚至不同 source）提交相同内容时**共享同一对象**，
  `event_payload_objects.ref_count` 记录引用数；
- 对象不可变：同一键的内容永远相同，因此重复 PUT / 崩溃重传绝对安全。

### 提交状态机：协调对象上传与数据库事务（无半成品 / 无悬空引用 / 无重复投递）

对象上传（S3）与数据库事务无法用单一原子事务覆盖，提交由持久化状态机
（表 `payload_upload_pending`，规范化字节直接存在行内）协调：

1. **查重**：`(source, event_id)` 已存在 → 直接幂等返回，不触对象存储；
2. **登记状态机行**（独立事务，含规范化字节）：崩溃后字节仍在、可重放；
3. **锁内终结**（单数据库事务）：获取按摘要的事务级咨询锁 → **幂等上传对象**
   → upsert 对象元数据并维护引用计数 → 插入事件（payload 置 NULL，只挂摘要）
   → 建投递 → 删除状态机行。

对象 PUT 与“建立引用”在同一把咨询锁、同一事务内完成，与 GC 的“最终复核→
物理删除”严格互斥（GC 一节详述），因此即使对象在存储中已存在而数据库尚无
元数据行，也不会出现悬空引用；若对象恰被并发 GC 删除，锁释放后提交方幂等
重传同一内容寻址对象即可。

外部观察者只能看到“完全没有该事件”或“事件 + 投递 + 对象引用齐备”，不存在
可见半成品。任一步失败或进程重启：

- 状态机行保留（字节就在行内），由 **api 进程后台恢复任务**周期续跑，也可
  手动 `python -m app.payloadadmin recover` 立即接管；
- 恢复时在同一把咨询锁内幂等补传缺失对象并重放终结事务；事件已存在（重复
  提交完成）则清理残留；
- 上传成功但终结失败产生的“零引用对象”不会被立即删除，最终由 GC 的存储孤儿
  扫描在宽限期后清理。

同一 `(source, event_id)` 的并发提交：内容一致则等待先提交者完成并按重复返回；
内容不一致返回 `409 event_submission_in_progress`。对象存储不可用时提交返回
`503 payload_store_unavailable`（状态机行已持久化，稍后重试可断点续跑）。

### Worker 取载荷：先复核摘要，再签名

Worker 认领投递后，从对象存储按摘要取回字节，**先重新计算 SHA-256 并与事件
引用常量时间比对**，通过后才解析 JSON、解密订阅密钥并 HMAC 签名：

- 对象缺失 / 摘要不符（存储侧损坏或被篡改）/ 非合法 JSON：**拒绝签名投递**，
  尝试明细记为新结果 `payload_integrity`，与普通失败一样按该投递钉住版本的
  退避/重试/死信语义结算（修复对象后重试即可成功）；
- 旧 JSONB 数据（在线迁移未完成）自动回退读数据库列，**双读期间投递不中断**。

### 旧 JSONB 数据的在线迁移与双读切换（可断点续跑）

升级前已存在的 `events.payload` JSONB 数据用管理命令在线迁移到对象引用，
**不需要停机、不影响投递**。迁移可在 `docker compose up` 后随时执行（API 与
Worker 持续运行，期间 Worker 对未迁移行读 JSONB、对已迁移行读对象，双读不
中断）；状态既可经 CLI `status` 查看，也可随时只读访问
`GET http://localhost:8000/api/v1/payloads/status`：

```bash
# compose 内（推荐反复运行直到 migration.status=completed/remaining=0；
# 幂等、断点续跑、可多副本并发；空批/短批只在确无旧载荷时才完成）
docker compose run --rm api python -m app.payloadadmin migrate
#   可选：--batch-size N（默认 200）、--wait-seconds N（默认 30：空批/短批
#   因并发迁移者持锁而无进展时，在同一次运行内等待并重试回访这些行的最长秒数）

# 迁移完成、确认无 remaining 后，分批回收事件行内冗余 JSONB 字节
# （此步骤前读路径是“对象优先、JSONB 兜底”；清空后只读对象）
docker compose run --rm api python -m app.payloadadmin clear-legacy

# 查看迁移/对象/引用/GC 状态（CLI）
docker compose run --rm api python -m app.payloadadmin status
# HTTP：只含计数，绝不含载荷内容（字段保持向后兼容）
curl -s localhost:8000/api/v1/payloads/status | python3 -m json.tool
```

本地一键启动后核验迁移（Docker Compose 一键启动，无需额外依赖）：

```bash
docker compose up --build                 # 启动 db/minio/api/worker/receiver
# 另开终端，并发跑两个迁移进程验证可并发、不死锁、不漏行（可再开更多）：
docker compose run --rm api python -m app.payloadadmin migrate --batch-size 50 &
docker compose run --rm api python -m app.payloadadmin migrate --batch-size 50 &
wait
# 通过只读 HTTP API 查看迁移结果（保留全部既有字段）：
curl -s localhost:8000/api/v1/payloads/status | python3 -m json.tool
```

请求：

```bash
$ curl -s localhost:8000/api/v1/payloads/status | python3 -m json.tool
```

响应（字段均为实际返回；对象存储后端为 MinIO 时 `store_mode="s3"`、
`bucket="webhook-payloads"`，离线 `local` 后端 `bucket=null`）。

迁移进行中（或最后一批刚提交的瞬间）看到的是 `running`，且两个剩余数
**必然相等**——整次响应在同一个只读数据库快照内读取：

```json
{
    "store_mode": "s3",
    "bucket": "webhook-payloads",
    "total_events": 128,
    "legacy_events_pending": 17,
    "payload_objects": 22,
    "total_references": 111,
    "total_object_bytes": 4207,
    "pending_submissions": 0,
    "gc_candidates": 0,
    "gc_grace_seconds": 3600,
    "migration": {
        "status": "running",
        "processed": 111,
        "remaining": 17,
        "last_event_id": 112,
        "last_error": null,
        "updated_at": "2026-10-03T09:11:58.842017+00:00"
    },
    "gc_runs": []
}
```

迁移全部完成后：

```json
{
    "store_mode": "s3",
    "bucket": "webhook-payloads",
    "total_events": 128,
    "legacy_events_pending": 0,
    "payload_objects": 37,
    "total_references": 128,
    "total_object_bytes": 4821,
    "pending_submissions": 0,
    "gc_candidates": 0,
    "gc_grace_seconds": 3600,
    "migration": {
        "status": "completed",
        "processed": 128,
        "remaining": 0,
        "last_event_id": 130,
        "last_error": null,
        "updated_at": "2026-10-03T09:12:41.553102+00:00"
    },
    "gc_runs": [
        {
            "id": 6,
            "status": "completed",
            "candidates": 2,
            "deleted_objects": 1,
            "rescanned_store": false,
            "last_error": null,
            "started_at": "2026-10-03T08:30:00.123456+00:00",
            "finished_at": "2026-10-03T08:30:02.481205+00:00"
        }
    ]
}
```

字段说明：`legacy_events_pending`/`migration.remaining` 为 0 即旧 JSONB 已全部
挂上对象引用；`payload_objects` 是内容去重后的对象数，`total_references` 为
引用总数（应等于已迁移/新格式事件数）；`migration.status` 为
`running/completed/failed`，对象上传失败的批次整批回滚时为 `failed` 且
`last_error` 记录原因（剩余集合不变，重跑 `migrate` 即续跑并清回 `running`）。

**状态读一致性（单次响应来自同一数据库视图）**：接口的状态行与全部计数
（含 `legacy_events_pending` 与 `migration.remaining` 两处剩余数）在单个
`REPEATABLE READ READ ONLY` 事务的同一快照内读取，因此同次响应中的两个剩余数
恒等，绝不可能出现一个为 0、另一个非 0 的自相矛盾；接口纯只读，绝不推进或
重开迁移。响应状态在该快照上即时裁决：除**持久化 `failed` 一律保留**（连同
`last_error`）外，快照中仍可见旧行即报 `running`、清零即报 `completed`
（所以最后一批恰在查询期间提交时，提交前的请求看到 `running/N`、提交后的
请求看到 `completed/0`，二者各自自洽，不会出现 `running` 而 `remaining=0`）。
**`completed` 只在全库确无旧载荷（`remaining=0`）时写入**：并发下某个进程拿到
空批或短批（剩余旧事件正被别的迁移进程 `SKIP LOCKED` 持锁，对端随后可能整批
回滚）绝不会谎报完成；服务启动与每次 `migrate` 还会把“误标 `completed` 但仍有
旧行”的陈旧状态自动重开为 `running` 并补迁（即便陈旧状态尚未被持久化纠正，
只读状态接口也会按同快照剩余数直接呈现 `running`，不谎报完成）。本接口只返回
计数与状态，绝不返回载荷内容。

迁移特性（与密钥迁移同一套“取批 `SKIP LOCKED` → 处理 → 提交”模式）：

- **每批一个事务、进度持久化**在 `payload_migration_state`；**领取不用单调 id
  游标**——每批都从“仍待迁移集合”（`payload_digest IS NULL`，部分索引）重新
  领取，行迁移成功即出集合。因此某进程锁住较早事件后上传失败回滚、另一进程
  跳锁处理较晚事件时，回滚释放的较早行在重跑中仍可被回访，不会因游标越过而
  永久漏迁（`last_event_id`/`processed` 仅为观测高水位/已挂接计数，不参与领取）；
- **空批/短批的完成裁决**：空批或短批都不代表完成——只有提交本批后
  `COUNT(*) WHERE payload_digest IS NULL = 0`（没有任何持锁者还留着旧行）才在
  批内标记 `completed`；空批但剩余 > 0 时返回 0 且保持 `running`，CLI 会以
  0.2s 间隔等待并重试（`--wait-seconds`，默认 30s），让失败批次回滚释放的行
  在同一次运行内被回访迁完；等待超时仍无进展（疑似对端僵死持锁）则保持
  `running` 退出并提示重跑，**绝不标记 completed**；
- **并发取锁按统一顺序，杜绝死锁**：多个迁移进程用 `FOR UPDATE SKIP LOCKED`
  领取互不相交的事件批次（如一批事件顺序是 X、Y，另一批恰好是 Y、X）。批次
  先在内存中汇总全部所需摘要，**按咨询锁实际键 `(classid,objid)` 的全局统一
  顺序一次取齐**（同一锁键只取一次），再幂等上传对象、逐事件挂引用。所有并发
  批次取锁顺序一致，不可能形成 AB-BA 等待环；锁贯穿“上传对象 → 挂引用”全程，
  与 GC 的“最终复核 → 物理删除”对同一摘要严格互斥；
- 对象按需幂等上传，旧事件与新事件的相同内容**复用同一去重对象**；挂引用是
  “仅当 `payload_digest` 为空”的**防卫性条件更新**，重复运行不重复计数、
  不新增引用（`processed` 只随实际挂接的行数增加）；
- 对象存储暂时不可用时**整批回滚**（进度不前、引用不落库），运行在独立事务
  标记 `failed`（批次事务内的状态写入会随回滚丢失，故失败状态在事务外落库），
  恢复后重跑即整批断点续跑、已上传的零引用对象由 GC 孤儿扫描清理；
- `clear-legacy` 只清已挂对象引用的行，因此任何时刻双读都有数据源。

### 垃圾回收（幂等：引用复核 + 宽限期，防误删）

载荷对象只在**确认不再被任何事件引用**后回收。GC 分阶段、可反复安全运行：

```bash
# 标记 + 回收（建议定时执行，例如每小时一次）
docker compose run --rm api python -m app.payloadadmin gc

# 同时扫描对象存储里“有对象、数据库无元数据”的孤儿（如崩溃残留），
# 首轮只登记，过了宽限期后的后续 gc 才真正删除
docker compose run --rm api python -m app.payloadadmin gc --rescan-store
```

删除一个对象前有五重保护，**并发提交、崩溃恢复、旧数据迁移或死信重放正在
复用的对象绝不会被误删——即使该对象在存储中已存在而数据库尚无元数据行**
（`--rescan-store` 登记的存储孤儿）：

1. 标记阶段只收集 `ref_count = 0` 的对象；
2. `NOT EXISTS payload_upload_pending`：进行中的提交（引用尚未在终结事务建立）
   不进入候选；存储孤儿扫描也跳过存在进行中提交的键；
3. **宽限期**（`PAYLOAD_GC_GRACE_SECONDS`，默认 3600 秒）：候选首次见后必须
   持续零引用超过宽限期；引用在期间重建的对象被“复活”保留；
4. 删除时在**单个数据库事务**内“按摘要咨询锁 + 候选行/元数据行锁
   （`FOR UPDATE`）→ 最终复核引用计数与进行中提交 → 物理删对象 → 删元数据”，
   锁贯穿物理删除全程；
5. **按摘要的事务级咨询锁**是互斥的关键：所有建立引用的路径（新提交终结、
   崩溃恢复 `recover`、旧数据 `migrate`）都在**同一数据库事务、同一把咨询锁
   内**完成“加锁 → 幂等 PUT 对象 → 建元数据与引用”。咨询锁不依赖元数据行
   是否存在，因此“存储里有对象、数据库无元数据”的孤儿也被覆盖——
   - 提交方先持锁：GC 在锁上等待，提交后复核必见引用 → 复活保留；
   - GC 先持锁并删除：提交方等锁后把同一内容寻址对象**幂等重传**再建引用，
     事件引用永远指向一个真实存在且摘要一致的对象，无悬空引用。

   对象物理删除失败（S3 5xx/超时等）时只重置该候选的宽限计时并提交事务，
   下一轮 GC 幂等重试；删除接口本身幂等（404 视为成功），不改变任何引用
   计数，也不破坏事件提交的幂等与状态机语义。

宽限期默认 1 小时：因此典型节奏是**定时跑 `gc`**（第一轮标记、后续轮删除到期
候选）。`gc` 幂等，重复运行只会推进真正到期且仍零引用的对象。

#### 通过 HTTP API 查询回收状态

GC 总览（候选数、已过宽限期的到期数、最老候选等待时长、进行中提交数与
最近运行记录；只读、只含计数，绝不含载荷内容）：

```bash
$ curl -s localhost:8000/api/v1/payloads/gc | python3 -m json.tool
{
    "gc_grace_seconds": 3600,
    "candidates": 2,
    "due_candidates": 1,
    "oldest_candidate_age_seconds": 4021.7,
    "pending_submissions": 0,
    "recent_runs": [
        {
            "id": 17,
            "status": "completed",
            "candidates": 2,
            "deleted_objects": 1,
            "rescanned_store": true,
            "last_error": null,
            "started_at": "2026-10-02T08:30:00.123456+00:00",
            "finished_at": "2026-10-02T08:30:02.481205+00:00"
        }
    ]
}
```

按对象摘要查询单个对象的回收状态（含元数据是否存在、引用计数、预计可删除
时刻、是否有进行中提交）：

```bash
$ curl -s localhost:8000/api/v1/payloads/gc/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
    | python3 -m json.tool
{
    "digest": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "is_candidate": true,
    "first_seen_at": "2026-10-02T07:23:00.000000+00:00",
    "eligible_at": "2026-10-02T08:23:00.000000+00:00",
    "eligible_now": true,
    "size_bytes": 4,
    "ref_count": 0,
    "object_metadata_exists": true,
    "pending_submission": false,
    "gc_grace_seconds": 3600
}
```

存储孤儿（元数据行不存在）的查询响应中 `object_metadata_exists=false`、
`size_bytes/ref_count=null`；摘要不是 64 位十六进制时返回
`400 {"detail":{"code":"invalid_digest",...}}`。物理回收仍由管理命令
`python -m app.payloadadmin gc` 触发，HTTP 接口只读。

### 载荷对象存储配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PAYLOAD_STORE_MODE` | `s3` | `s3`（S3 兼容）或 `local`（本地目录，仅离线联调/测试） |
| `S3_ENDPOINT_URL` | `http://minio:9000` | S3 endpoint（path-style；compose 内用服务名） |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | `minioadmin` / `minioadmin` | S3 凭据 |
| `S3_BUCKET` | `webhook-payloads` | 载荷桶（不存在启动时自动创建） |
| `S3_REGION` | `us-east-1` | 签名区域（SigV4） |
| `PAYLOAD_MAX_BYTES` | `1048576` | 单载荷大小上限（字节），超限提交返回 413 |
| `PAYLOAD_GC_GRACE_SECONDS` | `3600` | GC 宽限期：引用归零后至少等待多久才允许删除 |
| `PAYLOAD_STALE_AGE_SECONDS` | `60` | 提交状态机判定为崩溃残留前的最短年龄（秒） |
| `PAYLOAD_RECOVER_INTERVAL_SECONDS` | `15` | api 后台恢复巡检间隔（秒） |
| `PAYLOAD_LOCAL_DIR` | `/var/lib/webhook/payloads` | `local` 模式的对象目录 |

> S3 客户端是仓库内置的最小 **AWS Signature V4**（path-style）实现，仅依赖
> `httpx`，可直接对接 MinIO 与 AWS S3 / 其他兼容服务；对接 AWS 时把
> `S3_ENDPOINT_URL` 改为对应区域 endpoint（或使用 VPC endpoint）并更换凭据。

## 订阅密钥信封加密与主密钥轮换

订阅的 HMAC 密钥属于高敏感凭据。本服务以**信封加密（envelope encryption）**
保存密钥，并提供**在线主密钥轮换**：

```
保存配置版本时：
  随机 DEK（32B，每版本一把）
    └─ AES-256-GCM(DEK, 密钥明文, AAD = subscription_id + version_id)
         → secret_ciphertext          （密文钉死在行上，换行无法解密）
    └─ AES-256-GCM(主密钥, DEK, AAD 绑定 key_id)
         → secret_dek_wrapped + secret_key_id
```

- **主密钥不落库**：只存在于本地密钥环（环境变量或 JSON 文件），数据库中
  只有密文与被包裹的 DEK；
- **明文不暴露**：API 响应、查询接口、日志都不含密钥明文；Worker 仅在
  签名前解密，解密失败（未知 `key_id` / 认证失败）会**拒绝投递**并把
  `crypto_error` 记入投递尝试（可查询），与普通失败一样退避/重试/死信；
- **版本固定语义不变**：加密只改变密钥的存储格式，解密出的明文与原密钥
  逐字节一致，已钉住版本的投递（含重试/接管/重放）签名结果不变。

### 本地密钥环配置

密钥环格式（`active_key_id` 指向当前用于包裹**新** DEK 的主密钥）：

```json
{"active_key_id": "k1", "keys": {"k1": "<base64 编码的 32 字节密钥>"}}
```

两个环境变量，**`WEBHOOK_KEYRING_JSON`（非空时）优先于 `WEBHOOK_KEYRING_FILE`**：

| 变量 | 说明 |
| --- | --- |
| `WEBHOOK_KEYRING_JSON` | 密钥环 JSON 字符串（适合注入容器环境变量） |
| `WEBHOOK_KEYRING_FILE` | 密钥环 JSON 文件路径（适合挂载密钥文件） |

- **Docker Compose（一键）**：默认挂载 `./deploy/dev-keyring.json`（开发用
  固定密钥），`docker compose up --build` 开箱即用。**生产必须更换**：
  在 `.env` 里设置 `WEBHOOK_KEYRING_JSON`，或把
  `WEBHOOK_KEYRING_HOST_FILE` 指向自己的密钥文件。
- **生成新密钥**：

  ```bash
  python -m app.keyadmin generate-key
  # 或：python -c "import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())"
  ```

- api 与 worker 必须使用**同一份**密钥环配置；密钥环在进程启动时加载，
  修改后需重启进程（`docker compose restart api worker`，滚动重启不影响投递）。
- 未配置密钥环时：创建订阅/发布版本返回 `503 keyring_not_configured`
  （绝不落明文），读取接口不受影响；已加密版本的投递以 `crypto_error` 结算。

### 明文存量的批量迁移（migrate）

升级前已存在的明文版本记录，用迁移命令批量转为信封格式：

```bash
# 容器内（compose）：
docker compose run --rm api python -m app.keyadmin migrate
# 本地：
python -m app.keyadmin migrate --batch-size 200
```

- **幂等、断点续跑**：每批一个事务，已加密的行不会重复处理；中断后重跑
  自动从剩余明文行继续；可同时跑多个迁移进程（行锁 `SKIP LOCKED` 分批）。
- **投递不中断**：迁移期间 Worker 对未迁移行按旧明文格式读取、对已迁移行
  按信封格式解密，两种格式均可正常投递。
- 迁移同时清空 `subscriptions.secret` 冗余列中的遗留明文。

### 在线主密钥轮换（rotate）

轮换只**重包裹 DEK**（解包后用新主密钥重新包裹），密钥密文本身不变，
因此不需要触碰任何密钥明文，投递全程不中断：

```bash
# 1) 生成新密钥并并入密钥环：keys 中同时保留新旧两把，active_key_id 指向新密钥；
#    重启 api/worker（滚动重启，投递不中断）。此后新版本即按新密钥包裹。
python -m app.keyadmin generate-key

# 2) 重包裹全部存量 DEK 到新 key_id（幂等、断点续跑、可并发）
docker compose run --rm api python -m app.keyadmin rotate --to k2

# 3) 确认无引用后移除旧密钥（带守卫：仍有记录引用旧 key_id 时拒绝移除）
docker compose run --rm api python -m app.keyadmin remove-key k1
#    文件型密钥环会直接改写文件（留 .bak 备份）；env 型会提示可安全删除。
#    随后从密钥环配置中删除旧密钥并重启 api/worker。
```

- **进度持久化**：每次轮换在 `key_rotations` 表记录运行状态
  （`running/completed/failed`、已处理条数、游标），崩溃或失败后重跑同一
  命令即断点续跑；同一目标 `key_id` 至多一条进行中运行，多个轮换进程会
  接管同一运行并并发分批处理。
- **失败恢复**：源 `key_id` 不在密钥环或 DEK 解包认证失败时，当批回滚、
  运行标记 `failed` 并记录错误；修复密钥环后重跑即可继续。
- **移除守卫**：`remove-key` 在仍有任何配置版本引用该 `key_id`、或它是
  活跃密钥时拒绝执行。

### 状态与错误查询

```bash
# 密钥环 / 迁移 / 轮换总览（CLI）
docker compose run --rm api python -m app.keyadmin status

# HTTP API（只含 key_id 标识符，绝不含密钥材料）
curl -s localhost:8000/api/v1/crypto/status | python3 -m json.tool
```

```json
{
  "keyring_configured": true,
  "active_key_id": "k2",
  "key_ids": ["k2"],
  "plaintext_versions_pending": 0,
  "encrypted_versions_by_key_id": {"k2": 3},
  "unknown_key_ids_in_use": [],
  "rotations": [{"id": 1, "new_key_id": "k2", "status": "completed",
                 "processed_count": 3, ...}]
}
```

`unknown_key_ids_in_use` 列出数据库引用但本地密钥环中不存在的 `key_id`
（例如旧密钥被过早移除）：这些版本的投递会被拒绝，投递尝试记录
`outcome = "crypto_error"`（`GET /deliveries/{id}/attempts` 可查，
`error_message` 含具体 `key_id` 与失败分类），并参与正常的退避/重试/死信
结算——把密钥加回密钥环并重启 worker 后即可恢复，死信可正常重放。

## 出站目标安全策略（SSRF 防护）

订阅目标 URL 是用户提供的，Worker 会向其发起服务端请求，因此必须防止把投递
流量导向内网基础设施或云实例元数据端点（SSRF）。策略在**两个时刻**执行，
规则完全一致：

1. **入口校验（API 进程）**：创建订阅（`POST /subscriptions`）与发布配置版本
   （`POST /subscriptions/{id}/versions`）时；
2. **投递校验（Worker 进程）**：每次投递尝试（含每一次重试、租约接管后的再投递）。

### 校验规则

- **协议**：仅允许 `http`、`https`，其余（`ftp`、`file`、`gopher` …）一律拒绝；
- **用户信息**：URL 禁止包含用户名/密码（`http://user:pass@host/…` 拒绝），
  凭据应放在 HMAC 签名或自定义请求头中；
- **地址全量校验**：解析主机得到的**每一个**地址都必须通过；只要其中一个属于
  阻止类别，整个目标即被拒绝（防止攻击者用“一个公网 + 一个内网”的多地址记录
  试探）。

默认阻止的地址类别：

| 类别 | 示例 |
| --- | --- |
| 回环 loopback | `127.0.0.0/8`、`::1` |
| 链路本地 link-local | `169.254.0.0/16`、`fe80::/10` |
| 私网 private | `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`fc00::/7`、`100.64.0.0/10`(CGNAT) |
| 组播 multicast | `224.0.0.0/4`、`ff00::/8` |
| 保留 / 未指定 | `240.0.0.0/4`、`0.0.0.0`、`255.255.255.255`、`::` |
| 云元数据 | `169.254.169.254`（AWS/Azure/GCE/OpenStack/阿里云等）、`fd00:ec2::254`、`metadata.google.internal` |

> IPv4-mapped IPv6（如 `::ffff:127.0.0.1`）会按内嵌 IPv4 地址分类，无法借
> 映射形式绕过。

### 显式放行（精确主机 / CIDR）

两类白名单，**放行优先**于默认阻止（但协议/用户信息规则不可放行）：

- `WEBHOOK_ALLOWED_HOSTS`：逗号分隔的**精确主机名**（大小写不敏感，不支持通配；
  带不带尾点等价）。命中后该主机解析出的全部地址放行——用于 Compose 内的
  `receiver` 这类服务名。
- `WEBHOOK_ALLOWED_CIDRS`：逗号分隔的 IP 或 CIDR（单 IP 视同 `/32`、`/128`）。
  地址落在其中即放行，例如 `WEBHOOK_ALLOWED_CIDRS=172.16.0.0/12,10.0.0.5`。

配置在 api 与 worker 两个进程必须一致（docker-compose 已用相同的变量传递）。
CIDR 配置项含非法条目时进程会在启动时直接报错。

### 防 DNS 重绑定

入口校验与实际连接之间存在时间窗，若仅在创建订阅时解析一次，攻击者可在投递时
把域名重绑定到内网地址。Worker 的做法：

1. **每次尝试都重新解析**（不缓存跨尝试结果），并再次执行完整策略；
2. 校验通过后，把“**本次**校验通过的地址”直接交给自定义网络后端建立 TCP 连接，
   HTTP 客户端不再自行做第二次 DNS——校验的地址即连接的地址；
3. 请求行与 `Host` 头仍使用原主机名；HTTPS 的 **SNI 与证书名校验**也仍以原主机名
   进行（只在 TCP 层连接固定 IP），因此虚拟主机与 TLS 行为不变；
4. **重定向不自动越权**：客户端的自动跟随已关闭，收到 3xx（301/302/303/307/308）
   时对 `Location` 解析出的下一跳重新执行“结构校验 → 重新解析 → 全量地址校验”，
   任何一跳命中阻止类别即整次投递失败；上限 `WEBHOOK_MAX_REDIRECTS`（默认 5）防环。
   301/302/303 按 RFC 改写为 GET，307/308 保留方法与载荷。

### 失败如何结算

- **入口失败**（创建/发布时）：返回 `422`，响应体为结构化错误，便于调用方区分：

  ```json
  {"detail": {"code": "blocked_address",
              "message": "主机 169.254.169.254 解析到被安全策略阻止的地址: …",
              "host": "169.254.169.254"}}
  ```

  错误码：`invalid_scheme`、`userinfo_forbidden`、`invalid_url`、`dns_error`、
  `no_address`、`blocked_address`、`cloud_metadata_host`。
- **投递失败**（Worker 解析/连接/任意重定向跳被拒绝）：尝试明细记录为新结果
  `outcome = "security_blocked"`（`GET /deliveries/{id}/attempts` 可查询，
  `error_message` 含具体类别与被拒地址），并与普通网络失败**完全一样**地参与
  该投递所钉住版本的指数退避、重试次数、死信结算；严格顺序、租约接管、版本
  固定语义均不受影响。

### Compose 中的 receiver 为何默认可用

Worker 与 API 通过 Docker 网络用服务名 `receiver` 访问接收器，该名字解析出的是
内网地址（默认会被阻止）。因此 `docker-compose.yml` 默认设置
`WEBHOOK_ALLOWED_HOSTS=receiver` 显式放行该服务名，**一键启动开箱即用**；
在 Compose 外做本地裸机联调（目标写 `http://127.0.0.1:8001/...`）时，把
`127.0.0.1`（或 `localhost`）追加到白名单即可：

```bash
WEBHOOK_ALLOWED_HOSTS=receiver,127.0.0.1,localhost docker compose up --build
```

可用接收器的 `POST /redirect?to=<URL>` 端点观察逐跳策略：`to=/receive` 为
放行的相对重定向；`to=http://169.254.169.254/...` 会在第二跳被 Worker 拒绝
（投递记录为 `security_blocked`）。

## 本地回调接收器

默认随 Compose 启动（容器内 8001，宿主机 `http://localhost:8001`）：

| 方法 | 路径 | 行为 |
| --- | --- | --- |
| POST | `/receive` | 200；校验并记录签名 |
| POST | `/fail` | 500（可用 `/control/fail?enabled=false` 关闭，用于演示重放成功） |
| POST | `/fail/{n}` | 同一 delivery 前 n 次 500，之后 200 |
| POST | `/slow?seconds=5` | 延迟响应（用于租约实验） |
| POST | `/redirect?to=<URL>` | 307 重定向（保留方法/载荷），用于验证 Worker 重定向逐跳安全校验 |
| POST | `/control/fail?enabled=true|false` | 开关 `/fail` |
| GET | `/received?limit=100` | 最近收到的投递（内存保存，重启清空） |
| POST | `/received/reset` | 清空记录 |
| GET | `/health` | 健康检查 |

设置 `RECEIVER_SECRET`（默认 `dev-signing-secret`）后，接收器强制校验签名；
留空则只记录不强制。`RECEIVER_TIMESTAMP_TOLERANCE_SECONDS` 控制时间戳偏差
（默认 300 秒，设为 0 关闭时间戳检查）。

## 配置

全部通过环境变量配置，默认值开箱即用（见 `.env.example`，可复制为 `.env`，
`docker compose` 会自动加载）：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql://webhook:webhook@db:5432/webhooks` | 数据库 DSN |
| `POSTGRES_USER/PASSWORD/DB/PORT` | `webhook/webhook/webhooks/5432` | db 服务与暴露端口 |
| `API_PORT` / `RECEIVER_PORT` | `8000` / `8001` | 宿主机映射端口 |
| `LEASE_SECONDS` | `30` | 认领租约时长；过期可被接管 |
| `HTTP_TIMEOUT_SECONDS` | `10` | 单次投递 HTTP 超时（应小于租约） |
| `WORKER_POLL_SECONDS` | `1` | 无任务时 Worker 轮询间隔 |
| `MAX_ATTEMPTS` | `6` | 最大尝试次数，达到后进死信；仅作新建订阅 revision=1 的默认值，发布版本可按订阅覆盖 |
| `BACKOFF_BASE_SECONDS` | `5` | 指数退避基数：`base*2^(n-1)`；同上，可被版本覆盖 |
| `BACKOFF_CAP_SECONDS` | `300` | 退避间隔上限；同上，可被版本覆盖 |
| `RECEIVER_SECRET` | `dev-signing-secret` | 接收器验签密钥，空则不强制 |
| `RECEIVER_TIMESTAMP_TOLERANCE_SECONDS` | `300` | 签名时间戳允许偏差 |
| `WEBHOOK_ALLOWED_HOSTS` | `receiver`（仅 compose 内） | 出站精确主机名白名单（逗号分隔），命中即放行其全部解析地址 |
| `WEBHOOK_ALLOWED_CIDRS` | 空 | 出站 CIDR/IP 白名单（逗号分隔），地址落入即放行，优先于默认阻止 |
| `WEBHOOK_MAX_REDIRECTS` | `5` | Worker 跟随重定向的最大跳数（每跳重新做同一安全校验） |
| `WEBHOOK_KEYRING_JSON` | 空 | 密钥环 JSON（非空时优先）；compose 默认改用挂载文件 |
| `WEBHOOK_KEYRING_FILE` | `/run/keyring/keyring.json`（compose 内） | 密钥环 JSON 文件路径；compose 默认挂载 `./deploy/dev-keyring.json` |
| `PAYLOAD_STORE_MODE` | `s3` | 载荷对象存储后端：`s3` 或 `local`（本地目录，仅离线联调） |
| `S3_ENDPOINT_URL` | `http://minio:9000` | S3 兼容 endpoint（path-style） |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | `minioadmin` / `minioadmin` | S3 凭据（同时是 MinIO root 凭据） |
| `S3_BUCKET` / `S3_REGION` | `webhook-payloads` / `us-east-1` | 载荷桶（自动创建）与 SigV4 区域 |
| `S3_API_PORT` / `S3_CONSOLE_PORT` | `9000` / `9001` | MinIO S3 API / Web 控制台的宿主机端口 |
| `PAYLOAD_MAX_BYTES` | `1048576` | 单载荷大小上限（字节），超限提交返回 413 |
| `PAYLOAD_GC_GRACE_SECONDS` | `3600` | GC 宽限期：引用归零后至少多久才允许删除对象 |
| `PAYLOAD_LOCAL_DIR` | `/var/lib/webhook/payloads` | `local` 后端的对象目录（仅离线联调/测试） |

### 出站策略的启动与访问

- **Docker Compose（一键）**：`receiver` 已在默认白名单中，
  `docker compose up --build` 后直接可把订阅指向
  `http://receiver:8001/receive`，无需任何额外配置。
- **本机裸机联调**：接收器与 API/Worker 跑在宿主机时目标是回环地址，需显式放行：
  `WEBHOOK_ALLOWED_HOSTS=127.0.0.1,localhost`（仓库自带的验证脚本已自动带上）。
- 指向真正的公网 HTTPS 回调地址无需任何放行；只有回环/内网/链路本地/元数据等
  默认阻止类别才需要白名单。策略细节见
  [“出站目标安全策略”](#出站目标安全策略ssrf-防护)。

默认 6 次尝试的退避时刻（相对首次失败）：5s、15s、35s、75s、155s
（间隔 5/10/20/40/80 秒）。联调想快速看到死信，可调小
`BACKOFF_BASE_SECONDS` / `BACKOFF_CAP_SECONDS`。

## 数据库表

- `event_payload_objects`：不可变载荷对象的元数据，主键即规范化 JSON 的
  SHA-256 摘要；保存 `size_bytes` 与 `ref_count`（引用该对象的事件数）。
  同内容全库去重，字节本体在对象存储中。
- `events`：事件，`(source, event_id)` 唯一。`payload_digest` 外键引用
  `event_payload_objects.digest`；`payload` JSONB 列仅承载迁移前的旧数据，
  新事件为 NULL，迁移并 `clear-legacy` 后旧数据也清空。
- `payload_upload_pending`：提交状态机的持久化状态（以 `(source,event_id)`
  唯一，内含规范化字节），协调对象上传与数据库事务；崩溃后由后台恢复/
  `payloadadmin recover` 续跑，正常提交终结时删除。
- `payload_migration_state`：旧 JSONB 在线迁移的单行进度（状态、观测高水位
  事件 id、已挂接数、错误）。领取不依赖该游标——每批从仍待迁移集合
  （`payload_digest IS NULL`）重新领取，故并发回滚的行可被回访；仅在确无
  旧载荷时标记 completed，支持断点续跑、并发与失败恢复。
- `payload_gc_candidates` / `payload_gc_runs`：GC 的零引用候选（带首次见
  时间戳，实现宽限期）与回收运行审计记录。
- `subscriptions`：订阅身份（source、启用状态、`current_revision`）。
  `target_url` 列随当前版本冗余同步；`secret` 冗余列不再保存明文（统一置空），
  权威配置在版本表。
- `subscription_versions`：不可变配置版本，`(subscription_id, revision)` 唯一。
  保存 `target_url`、重试参数与密钥的**信封加密列**（`secret_ciphertext`、
  `secret_dek_wrapped`、`secret_key_id`）；`secret` 明文列仅用于迁移前的旧
  记录，迁移/新写入后置空。`created_at` 为该版本成为当前版本的边界时刻，
  `superseded_at` 为被取代时刻。密钥从不出现在任何 API 响应中。
- `key_rotations`：主密钥轮换运行记录（状态、已处理条数、游标、错误），
  持久化轮换进度，支持断点续跑与失败恢复；同一目标 `key_id` 至多一条
  进行中运行（部分唯一索引）。
- `deliveries`：投递记录。`config_version_id` 外键把投递钉死在其创建时的版本上
  （重试/接管/重放都不改变，重放只新建记录并重新选择版本）。初始投递为
  `(chain_id, chain_seq=1)`；重放沿用同一 `chain_id` 且 `chain_seq` 递增，
  从而保留完整历史。`seq` 是订阅顺序号。
- `delivery_attempts`：每次尝试的 Worker、结果分类（success/http_error/
  network_error/timeout/**security_blocked**/**crypto_error**/
  **payload_integrity**）、HTTP 状态码、
  响应摘要（截断 2048 字符）、错误信息（security_blocked 时含被拒地址与类别；
  crypto_error 时含 key_id 与失败分类，不含密钥材料；payload_integrity 时含
  期望/实际摘要，不含载荷内容）、租约起止时间。

## 本地开发（不使用 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# 需要一个可连接的 PostgreSQL
export DATABASE_URL=postgresql://user:pass@localhost:5432/webhooks
# 本地密钥环（开发示例；生产用 keyadmin generate-key 生成并妥善保管）
export WEBHOOK_KEYRING_JSON='{"active_key_id":"dev-k1","keys":{"dev-k1":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}}'
# 事件载荷对象存储：
#   有 MinIO/S3 时用 PAYLOAD_STORE_MODE=s3 + S3_ENDPOINT_URL 等（见上表）；
#   纯本机联调可用本地文件后端，无需任何外部依赖：
export PAYLOAD_STORE_MODE=local
export PAYLOAD_LOCAL_DIR=./.local-payloads
uvicorn app.main:app --reload --port 8000          # API
python -m app.worker                               # Worker（可起多个）
uvicorn app.receiver:app --port 8001               # 接收器

# 密钥管理（迁移 / 轮换 / 移除 / 状态）
python -m app.keyadmin status
# 载荷对象管理（旧 JSONB 迁移 / GC / 崩溃恢复 / 状态）
python -m app.payloadadmin status
python -m app.payloadadmin migrate
python -m app.payloadadmin gc --rescan-store
```

仓库还包含五个本地验证脚本（非 Docker 依赖，会自动拉起便携 PostgreSQL；
载荷对象用本地文件后端 `PAYLOAD_STORE_MODE=local`，无需 MinIO）：

- `test_e2e.py`：完整四进程拓扑，覆盖幂等、顺序、退避死信、重放、租约接管、
  配置版本 CAS 发布、无损切换、按钉住版本的重试参数结算与死信重放版本选择，
  以及出站安全策略（入口 422、Worker `security_blocked` 退避/死信结算、
  重定向逐跳校验）；
- `test_concurrency.py`：高并发下发布与事件提交的原子边界压力测试，
  并对每条收到的投递按其钉住版本密钥独立重新验签，证明重试不会跨界、不换密钥；
- `test_crypto.py`：密钥信封加密与轮换专项——落库无明文、API 不泄露、
  迁移期间新旧格式均可投递、migrate/rotate 幂等断点续跑、轮换只重包裹 DEK、
  旧密钥移除守卫、未知 key_id 拒绝投递并记录 `crypto_error`、修复后重放恢复、
  未配置密钥环时写入 503；
- `test_payloads.py`：载荷对象存储专项——内容寻址与跨事件去重（ref_count）、
  规范化键序归一、提交状态机崩溃恢复（补传对象、无悬空引用、不重复投递）、
  旧 JSONB 在线迁移与双读切换/clear-legacy、Worker 摘要校验
  （篡改对象 -> `payload_integrity`，恢复后重试成功）、GC 宽限/行锁复核/
  复活保护与 `--rescan-store` 孤儿回收；以及 `GET /payloads/status` 迁移状态
  读一致性（同一快照下两个剩余数恒等、有旧行 running/清零 completed、持久化
  failed 与 last_error 保留、只读不推进迁移、慢迁移者并发提交期间反复采样
  无自相矛盾响应）。
- `test_migrate_concurrency.py`：并发迁移专项——咨询锁按实际键统一顺序取齐
  且同键去重、两批 X/Y 事件顺序相反时确定性并发不死锁、多迁移者不同批次大小
  叠加 GC 压力下对象去重/引用计数/迁移进度精确且无悬空引用、上传失败整批
  回滚且 `failed` 状态在事务外持久化、恢复后重跑幂等成功、双读不中断；
  以及并发漏行修复：一方锁较早事件后上传失败回滚、另一方跳锁拿到短批/空批
  时绝不谎报 completed，回滚行在重跑中可回访并迁完，重复运行不重复计数/不
  新增引用，旧库残留的“completed 但仍有旧行”状态自动重开补迁。
- `test_gc_concurrency.py`：GC 与并发提交/恢复/迁移的引用互斥专项。
