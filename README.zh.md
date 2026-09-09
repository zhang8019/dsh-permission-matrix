# dsh-permission-matrix — DeepSeek Harness 权限矩阵插件

[English](README.md) | 中文

把 DSH 的权限从「几个固定档位」拆成**两个独立维度**并重新组合:

- **沙箱(读写边界)**:工作区只读 / 工作区读写 / 全电脑读写
- **审批(操作批准方式)**:人工审批 / 自动同意 / 自动风险审批 / 自动拒绝

两者组合出 **9 个可切换的执行类型**,外加**全局默认预设**与**LLM 机器人默认预设**两个维度——社交渠道(QQ / 微信 / 企微 / Telegram…)的会话可以用与 Web 会话不同的权限档位。

> 取代 `dsh-auto-classifier` 的单点 `auto` 预设:本插件保留它的核心思路(规则 + LLM 裁判 + 硬拒绝),但把预设表拆成完整的组合矩阵。

---

## 9 个执行类型

| # | 预设 id | 显示名 | 沙箱 | 审批 | 行为 |
|---|---|---|---|---|---|
| 1 | `ro-human` | 工作区只读权限 + 人工审批 | read-only | ask | 一切写入被沙箱拒绝,越权操作弹人工确认 |
| 2 | `ro-deny` | 工作区只读权限 + 自动拒绝 | read-only | never | 写入一律拒绝,无人审批环节(真正只读) |
| 3 | `ww-human` | 工作区读写权限 + 人工审批 | workspace-write | ask | 工作区内可写;越界操作弹人工确认(默认) |
| 4 | `ww-classify` | 工作区读写权限 + 自动风险审批 | workspace-write | ask | 工作区内可写;越界与高风险操作按风险分级裁决 |
| 5 | `ww-deny` | 工作区读写权限 + 自动拒绝 | workspace-write | never | 工作区内可写;越界操作一律拒绝 |
| 6 | `fa-human` | 全电脑读写权限 + 人工审批 | danger-full-access | ask | 文件全放行;需批准的操作交给人工 |
| 7 | `fa-deny` | 全电脑读写权限 + 自动拒绝 | danger-full-access | never | 文件全放行;需批准的操作一律拒绝 |
| 8 | `fa-auto` | 全电脑读写权限 + 自动同意 | danger-full-access | ask | 文件全放行;需批准的操作自动放行(硬拒绝保护) |
| 9 | `fa-classify` | 全电脑读写权限 + 自动风险审批 | danger-full-access | ask | 文件全放行;操作按风险分级裁决 |

### 为什么是 9 个而不是 12 个

3 沙箱 × 4 审批 = 12,但有三组功能重复:

- **自动同意在三种沙箱下等效**:`只读 + 自动同意` 里写操作被沙箱拒 → 自动批准 → 照样写成功,最终权限与 `全电脑 + 自动同意` 相同,只是每次多一次往返。故只保留一个。
- **自动风险审批在只读下与工作区读写下等效**:分类器对工作区内写入确定性放行,两者结果一致。故只保留工作区读写档。

## 关键设计:审批档只有两个合法值

`@deepseek-ai/dsh-user-approval` 的 `APPROVAL_POLICIES` 只有 `ask` / `never`。因此:

| 审批档 | 预设表里写的值 | 实际由谁实现 |
|---|---|---|
| 人工审批 | `ask` | 浏览器应答者(插件不干预) |
| 自动同意 | `ask` | **本插件**在 `approval/request` 返回 `allowed-once` |
| 自动风险审批 | `ask` | **本插件**在 `tools/pre-execute` + `approval/request` 分级裁决 |
| 自动拒绝 | `never` | DSH 原生确定性拒绝(插件不干预) |

插件通过 `takeover` 表按**当前会话的预设 id** 分流,未列出的预设全程 `next()`,行为与 DSH 原生一致。

## 自动风险审批的分级

判定顺序:

1. **硬拒绝(HARD)** → 直接拒绝,**人工也不能批准**,不可被"同意/转人工"推翻;
2. **工作区内结构放行**(write/edit/read 且目标在会话工作区内)→ 放行(受保护目标除外:`~/.dsh`、凭据、`.git/config|hooks`);
3. **允许规则**(常规 git、包管理器、语言运行时、PowerShell cmdlet 等)→ 放行;
4. **LLM 裁判**(可开关)→ 语义裁决;
5. **三档风险策略**(低 / 中 / 高 **各自**可选「放行 / 拒绝 / 转人工」):

| 风险级别 | 来源 | 默认策略 |
|---|---|---|
| **低** | 允许规则命中 / 工作区内操作 / 裁判判定安全 | 放行 |
| **中** | 规则未命中 / 裁判不确定 | 拒绝 |
| **高** | 裁判判定危险 | 拒绝 |
| **极高** | 硬拒绝清单 | **固定拒绝**(不可配置,人工也不能批准) |

`ask`(转人工)在完全权限下同样可用,经 `tools/pre-execute` 返回 `{kind:'ask'}` → approval seam。

**硬拒绝清单在设置页只读**,不可编辑——防止通过配置绕过"极高风险人工也不能批准"的硬边界。

## 全局默认 + LLM 机器人默认

| 选择器 | 作用域 | 存储位置 |
|---|---|---|
| 全局默认预设 | 新建的 Web / 常规会话 | DSH 原生 `permission` 命名空间的 `defaultPreset`(与 Settings → 权限 同源) |
| LLM 机器人默认预设 | 社交渠道会话(按工作区匹配) | 本插件的 `permission-matrix` 命名空间 |

机器人识别**不感知任何具体机器人插件**:只按会话工作区(cwd)匹配 `robotWorkspaces` 列表。机器人插件卸载后本插件照常运行,只是不再产生落在这些工作区的新会话。

## 安装

```sh
dsh plugin --profile <profile> add dsh-permission-matrix
```

本插件的 `cordis.patch.yml` 会:

1. 把 `permission` 行 restate 为上述 9 个预设;
2. 插入 `permission-matrix` 插件行。

> **若同时装有 `dsh-auto-classifier`**,请把它停用(两者争抢同一个 `permission` 行):
>
> ```yaml
> # <profile>/cordis.patch.yml
> - id: auto-classifier
>   name: dsh-auto-classifier
>   disabled: true
>   config: { enabled: false, presetName: auto }
> ```
>
> 注意 patch 条目必须同时带 `name` 字段,否则 `disabled` 不生效。

## 配置

设置 → **权限矩阵** 页面(或 `<profile>/cordis.patch.yml` 的 `permission-matrix` 行):

| 键 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | 总开关 |
| `takeover` | 见上表 | 预设 id → 审批档(`auto-allow` / `classify`) |
| `riskPolicies` | `{low:allow, medium:deny, high:deny}` | 三档风险策略(低/中/高各自 `allow`/`deny`/`ask`);极高风险固定拒绝 |
| `llmJudge` | `true` | LLM 裁判开关 |
| `judgeProvider` / `judgeModel` | 空 | 留空 = 跟随当前会话模型 |
| `judgeStages` | `both` | `both` / `fast` / `thinking` |
| `autoAllowHardGuard` | `true` | 自动同意档的硬拒绝保护 |
| `robotDefaultPreset` | `fa-auto` | 机器人会话默认预设 |
| `robotWorkspaces` | `[]` | 机器人会话工作区(绝对路径,含子目录) |
| `gitSnapshot` | `true` | 放行前 git 快照 |
| `gitSnapshotIntervalMs` | `30000` | 快照节流 |
| `auditLog` | `true` | 审计开关 |
| `auditFile` | `~/.dsh/permission-matrix/audit.jsonl` | 审计文件 |

配置非法(未知预设 id、非法档位)会在**加载期响亮失败**,不会静默降级。

## 审计

每次裁决写一行 JSONL:

```json
{"time":"2026-09-09T10:52:00.000Z","sessionId":"…","preset":"ww-classify","tool":"write","target":"D:\\out\\a.txt","risk":"medium","rule":"mid-policy:deny","source":"mid","decision":"deny","outcome":"blocked"}
```

只写文件与进程日志,**不进入模型 transcript**。

## 架构

```
src/
├── index.js           装配 + 三个钩子(tools/pre-execute、approval/request、session/created)
├── presets.js         9 预设的单一真源
├── preset-router.js   当前会话预设 → 是否接管、以哪档接管
├── decide.js          决策核心(纯函数:硬拒绝 → 区内放行 → 允许规则 → null)
├── rules.js           硬拒绝 / 允许规则表 + 字段投影
├── judge.js           LLM 裁判(两阶段 + 跟随会话模型 + 失败降级)
├── snapshot.js        Git 快照
├── audit.js           JSONL 审计
├── robot-presets.js   机器人工作区 → 默认预设
├── settings.js        settings 命名空间 + webServer 同源路由
└── client/index.js    设置页(手写 __ModuleLoader__ bundle)
```

## 测试

```sh
node --test tests/decide.test.js tests/hooks.test.js
```

覆盖:硬拒绝(删根目录 / 格式化 / 提权 / 强推)、工作区内放行、受保护目标、三档风险策略、防回环、机器人预设切换、配置校验、总开关。

## 参考与致谢

本插件的设计参考了以下三个社区插件(思路借鉴 + 取舍改进,**代码为独立实现**):

### 1. [dsh-auto-classifier](https://github.com/nanmicoder/dsh-auto-classifier) — 主要参考

- **借鉴**:单点 `auto` 预设的定位(低风险放行 / 危险拦截 / 沙箱升级自动裁决)、`tools/pre-execute` + `approval/request` 双钩子 + `{prepend:true}` 抢占、HARD/SOFT 风险分级、`Tool(pattern)` 规则语法、字段投影(命令类只扫 `command/code`、路径类只扫 `file_path`)、工作区内结构放行、LLM 裁判两阶段(快速过滤 + 思考复审)、拒绝日志与 denial 上限、Git 快照。
- **改进**:把「单点 auto」升级为 **3 沙箱 × 4 审批 = 9 个可组合预设**;风险分级从 2 档细化为**低/中/高 + 极高(固定拒绝)**,且三档**各自可配**放行/拒绝/转人工;新增全局默认 + LLM 机器人默认两个维度。
- **修正**:该插件用 `permissionPresets.current(session.events)`(旧签名),在 DSH 0.1.2-rc.1 下会被 `try/catch` 静默吞掉而失效;本插件改用正确签名 `current(session)` 并回退到投影读取。

### 2. [dsh-auto-approval-plugin](https://github.com/StyxNether/dsh-auto-approval-plugin) — 审批应答者参考

- **借鉴**:注册 `approval/request` 监听器返回 `allowed-once` 实现「自动批准」、从会话日志按 `callId` 取**真实工具参数**(不信任模型写的理由)、路径经 `realpath` 解析后判定区域归属、失败方向永远 `defer`(绝不误拒)。
- **改进**:本插件的「自动同意」档同样带**硬拒绝保护**(极高风险不自动放行),而非无条件放行。

### 3. [dsh-yolo-mode](https://github.com/SeverusZh/dsh-yolo-mode) — 分级裁决参考

- **借鉴**:用大模型裁决沙箱**升权申请**、`allow / judge / delegate / deny` 四值决策、`fail-closed`(超时/非法输出/模型不可用一律拒绝或转人工)、审计 JSONL 每行一次裁决。
- **改进**:本插件把「转人工」做成中/高三档的可选策略,并解决了「完全权限下无审批通道」的限制——利用 `tools/pre-execute` 返回 `{kind:'ask'}` 经 approval seam 转人工(见设计说明书 §0.1)。

### 其它参考

- DSH 官方文档:`docs/subsystems/approval.zh.md`(审批 seam 语义)、`docs/cookbook/extension-cookbook.zh.md`(permission-gate 范例)、`docs/cookbook/adding-a-settings-card.zh.md`(设置页两个半侧)。
- 硬拒绝清单的条目集合合并自上述三个插件的默认 deny/dangerous 规则表。

## License

MIT
