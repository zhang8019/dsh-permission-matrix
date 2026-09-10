# dsh-permission-matrix — DeepSeek Harness 权限矩阵插件

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

## 风险分级与判定顺序

1. **硬拒绝(HARD)** → 默认直接拒绝,**人工也不能批准**(`riskPolicies.hard = 'deny'`);配为 `ask` / `password` 时改为**密码批准**通道(见下节),但**不提供「放行」选项**;
2. **高风险(HIGH)** → 按 `riskPolicies.high` 分派;非盘根递归/批量删除、普通 `git push` 走此档,**工作区内路径豁免**;
3. **工作区内结构放行**(write/edit/read 且目标在会话工作区内)→ 放行(受保护目标除外:`~/.dsh`、凭据、`.git/config|hooks`);只读工具读取系统目录/配置同样放行——**读不是写**;
4. **允许规则**(常规 git、包管理器查询、语言运行时、PowerShell cmdlet 等)→ 放行;
5. **LLM 裁判**(可开关)→ 语义裁决;
6. **四档风险策略**(低 / 中 / 高 / 极高各自可选):

| 风险级别 | 来源 | 默认策略 | 可选值 |
|---|---|---|---|
| **低** | 允许规则命中 / 工作区内操作 / 裁判判定安全 | `allow` | `allow` / `deny` / `ask` / `password` |
| **中** | 规则未命中 / 裁判不确定 | `deny` | `allow` / `deny` / `ask` / `password` |
| **高** | 裁判判定危险 / 非盘根递归删除 / `git push` | `deny` | `allow` / `deny` / `ask` / `password` |
| **极高** | 硬拒绝清单(24 条) | `deny` | `deny` / `ask` / `password`(**不提供放行**) |

- `ask`(转人工)在完全权限下同样可用,经 `tools/pre-execute` 返回 `{kind:'ask'}` → approval seam(浏览器审批弹窗,点同意即放行);
- `password`(密码批准)= **挂起等密码**,由本插件自己的密码弹窗接管(见下节),与模型行为无关。

### 执行面识别(避免"提及即拦截")

HARD/HIGH 规则**只匹配真正会被执行的片段**:`executionSurface()` 会剥离注释、字符串字面量、变量赋值右侧与文件名。因此 `$m = "shutdown /s"`(仅赋值)、`# shutdown /s`(注释)、`Test-Path pm-sudo-notes.txt`(路径含关键词)、`Write-Host "..."`(输出文本)都不会再被误拦;真实执行 `shutdown /s` 依旧拒绝。

同理,只读形态与写入形态被区分开:`schtasks /query`、`net user`(列用户)、`icacls <路径>`(查 ACL)、`bcdedit /enum`、`diskpart /?` 等只读查询与帮助文本放行,对应的写/变更形态仍然拒绝。

### 「密码批准」——与放行 / 拒绝 / 转人工并列的第四种方式

**低 / 中 / 高 / 极高四档都可以选 `password`**：该档操作会被**挂起**（不失败），由本插件要求输入批准密码；输对了**当场执行**，输错或超时按拒绝处理。

1. 挂起时登记一条**待批准请求**(工具名 + 投影目标 + 指纹 + 风险档,审计 `outcome=password-required`);
2. 输入入口有三处(等价):
   - **密码弹窗**:注册进 `shell.overlay` 槽位,浮在整个应用之上——出现即输入密码点「批准并立即放行」,**被挂起的那次调用当场执行**,不需要模型重试;点「忽略」按拒绝处理;
   - **设置 → 权限矩阵 → 批准密码**:逐条「批准(放行一次)」,或「授权下一次需密码的操作」(通配);
   - 浏览器打开 `<Web 地址>/dsh-permission-matrix/approve`(纯表单页,无需前端脚本);
3. 超时(`approvalPasswordTtlMs`,默认 300 秒)未批准 → 该次调用按拒绝处理,但请求**仍留在列表里**:此时批准会签一张绑定该指纹的**一次性令牌**,模型重试即放行;
4. 令牌/交付都只用一次:指纹不同、会话不同或过期均不放行。

> `password` 与 `ask` 的区别:`ask`(转人工)交给浏览器审批弹窗,点一下「同意」就放行;
> `password` 必须**知道口令**,所以不会被"多点几次同意"绕过。极高风险档的 `ask` 与 `password` 等价(都走密码批准)。
>
> 极高风险默认仍为 `deny`(直接拒绝);设置页对极高风险档只提供「拒绝」与「需批准密码」,配置 `allow` 会在加载期 fail-closed 拒绝。
> **未设置批准密码 ⇒ 所有选了「需批准密码」的档一律拒绝**(弹窗也会明示"无法放行")。

**密码学**:口令以 **scrypt**(N=16384, r=8, p=1, 随机盐)哈希存储,明文既不落盘也**不回传浏览器**(`/status` 只回一个 `approvalPasswordSet` 布尔);`approvalPasswordHash` 不在设置页的可写键白名单里,只能经专用动作路由写入。待批准请求与令牌都在内存中,DSH 重启即失效。

**硬拒绝清单在设置页只读**,不可编辑——防止通过配置绕过硬边界。

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
| `riskPolicies` | `{low:allow, medium:deny, high:deny, hard:deny}` | 四档风险策略;极高风险只接受 `deny` / `ask` |
| `approvalPasswordHash` | 空 | 批准密码的 scrypt 哈希(设置页写入,明文不落盘;**不在**可写白名单,仅专用路由可写) |
| `approvalPasswordTtlMs` | `300000` | 密码批准窗口(毫秒):挂起等待时长 / 令牌有效期 |
| `hardApprovalPasswordHash` / `hardApprovalTtlMs` | — | **已废弃**(v0.3.0 旧键):仅兼容读取,写入一律用新键;已设口令不会因改名丢失 |
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

配置非法(未知预设 id、非法档位、极高风险档配 `allow`)会在**加载期响亮失败**,不会静默降级。

## 审计

每次裁决写一行 JSONL:

```json
{"time":"2026-09-09T10:52:00.000Z","sessionId":"…","preset":"ww-classify","tool":"write","target":"D:\\out\\a.txt","risk":"medium","rule":"mid-policy:deny","source":"mid","decision":"deny","outcome":"blocked"}
```

`outcome` 取值含 `passed` / `blocked` / `allowed-once` / `escalated-to-human` / `password-required`(挂起等密码) / `password-approved`(密码批准后放行) / `password-timeout` / `password-declined` / `password-cancelled`。

只写文件与进程日志,**不进入模型 transcript**。

## 架构

```
src/
├── index.js           装配 + 三个钩子(tools/pre-execute、approval/request、session/created)+ 密码批准闸门
├── presets.js         9 预设的单一真源
├── preset-router.js   当前会话预设 → 是否接管、以哪档接管
├── decide.js          决策核心(纯函数:HARD → HIGH → 区内放行 → 允许规则 → null)
├── rules.js           硬拒绝 / 高风险 / 允许规则表 + 执行面提取 + 字段投影
├── password-approval.js  「密码批准」通道(scrypt 哈希 + 待批准请求 + 挂起等待 + 一次性令牌)
├── judge.js           LLM 裁判(两阶段 + 跟随会话模型 + 失败降级)
├── snapshot.js        Git 快照
├── audit.js           JSONL 审计
├── robot-presets.js   机器人工作区 → 默认预设
├── settings.js        settings 命名空间 + webServer 同源路由(含批准页)
└── client/index.js    设置页 + 极高风险密码弹窗(手写 __ModuleLoader__ bundle,注册 settings.section 与 shell.overlay)
```

## 测试

```sh
node --test tests/decide.test.js tests/password-approval.test.js tests/hooks.test.js
```

69 条用例,覆盖:硬拒绝(删根目录 / 格式化 / 提权 / 强推 / `git reset --hard` / 系统级包安装)、高风险分派(非盘根递归删除 / `git push` / 动态执行变量)、工作区内递归删除豁免、受保护目标(路径类 + 命令类)、**拼接执行绕过(拆片段 / `iex` 动态执行 → 硬拒绝;纯输出文案不误伤)**、误拦回归(只读查询 / 注释与字符串里的关键词 / `_rsa` / 只读读系统目录 / 读 `settings.yaml`)、四档风险策略(含 `password` 值)、**密码批准(哈希校验 / 挂起与超时 / dismiss 与 abort / 一次性令牌 / 指纹与会话绑定 / fail-closed / 「弹窗输密码 → 挂起调用立即放行」端到端 / 中风险档同样生效)**、fail-closed 校验、防回环、机器人预设切换、总开关。

## 实测与修复记录(v0.2.0,2026-09-10)

在 **fa-classify**(全电脑读写)与 **ww-classify**(工作区读写)两档预设下做了真实工具调用实测(400+ 条审计记录),完整报告见 [docs/test-audit-2026-09-09.zh.md](docs/test-audit-2026-09-09.zh.md)。首轮实测暴露的问题**已在 v0.2.0 全部修复**:

**✅ 已修复的漏拦截(应拒却放行)**
- `git reset --hard` 完全无规则 → 新增 HARD 规则 `hard:git-reset-hard`;
- 系统级包安装(`apt-get` / `pip` / `winget install`)无规则 → 新增 HARD 规则 `hard:pkg-install-system`;
- **cmd 风格递归删除绕过**(`rd` / `rmdir` / `del /s /q` 不匹配 PowerShell 风格正则,实测能真删目录) → 新增 HARD 规则 `hard:rm-root-win-cmd` + 高风险规则;
- 非盘根递归删除被放行 → 新增**高风险(HIGH)档**,按 `riskPolicies.high` 转人工,**工作区内路径豁免**;
- 命令类工具写 `.dsh` 绕过保护 → 新增硬拒绝分支 `hard:protected-target`;
- 普通 `git push` 被放行 → 新增高风险规则 `high:git-push`(`--force` 变体仍为 HARD);
- `rm -rf ~/子目录` 不命中 → 高风险规则 `high:rm-recursive-unix` 覆盖。

**✅ 已修复的误拦截(应放行却被拒)**
- 只读查询与帮助文本误伤(`schtasks /query`、`net user`、`icacls <路径>`、`shutdown /?`、`Get-Help Stop-Computer`、`bcdedit /enum`、`diskpart /?`) → HARD 正则收窄为写/变更形态;
- 命令文本/注释/文件名/字符串里的关键词误伤(`shutdown`、`sudo`) → 执行面识别 `executionSurface()`;
- `_rsa` 宽泛后缀误伤(`my_rsa.txt`) → 凭据规则收窄为明确的私钥/凭据路径;
- `read` 工具读系统目录被拦(pwsh 读同一文件却放行) → 新增只读工具豁免(`READ_PATH_TOOLS`);
- 读取 `settings.yaml` 被当"篡改"拒 → 只读形态豁免,写入仍硬拒绝。

**✅ 拼接/动态执行绕过(2026-09-10 修复)**
- 原`已知限制`所列的**命令文本拼接绕过**(`$p1='Remove-'; $p2='Item -Recurse -Force C:\'; & $p1$p2`)已修复:实测还有更多同族漏拦(`$c='diskpart'; & $c`、`$x='shutdown /s'; iex $x`、`$cmd='net user hacker P@ss /add'; Invoke-Expression $cmd`),一并堵上。
- 做法:检测到**动态执行形态**(`& $var` / `. $var` / `iex $var` / `$a$b` 相邻变量)时,把**引号内的字符串**当真实命令再跑一遍 HARD 规则,并识别被拆开的 cmdlet 动词片段(`'Remove-'` 这类「动词 + 连字符结尾」,记为 `hard:concat-fragment`);
- 关键取舍:该检查**只在出现动态执行形态时**触发,所以 `Write-Host 'rm -rf /'` 这类纯文案不会被牵连——顺带修掉了此前"`Write-Host` 里提到危险词就被判 hard"的误拦(纯输出 cmdlet 现在一律按执行面匹配);
- 单独出现 `& $someExe --version` 这种正常动态调用**不硬拒绝**,落到高风险档 `high:dyn-call`(默认 deny,可配 `ask` / `password`);
- 残余风险:变量经多层间接(数组/哈希表/子表达式 `$(...)` 拼接、`[scriptblock]::Create`)仍可能绕过静态分析,依赖沙箱层与 LLM 裁判兜底。

**其它实测结论**
- ✅ HARD 清单本体可靠:全部硬拒绝规则按预期触发(含大小写 / 引号 / 嵌套变体);
- **ww 与 fa 差异只在沙箱层**:插件规则与 LLM 裁决逐项一致;ww 下工作区外写入由文件沙箱兜底拦截(插件放行但实际写不进),命令类写工作区外同样被沙箱拒;只读不受限;
- 沙箱升级通道放开后,规则漏洞仍可穿透执行——因此漏拦截修复在 ww 模式同样必要;
- v0.2.0 验证:单元测试 51 条全过;仓库 `src/` 与已安装 profile 的 `src/` SHA256 逐一一致(实机生效)。

## v0.3.0(2026-09-10):双重确认 → 批准密码

**失效根因(实测 + 审计证据)**:v0.2 的「极高风险双重人工确认」要求"模型在窗口内**原样重发同一条命令**"才能完成第 2 次放行。实际行为是:

- 第 1 次调用被拒后**模型不会原样重发**,而是改写命令(加 `Write-Host`、换变量、换工具)或改走别的路径 → 指纹(工具名 + 投影目标)随之变化,`hard-confirm-2` 分支永不命中;
- 审计日志 `~/.dsh/permission-matrix/audit.jsonl` 1064 条记录里 `hard-confirm-1` 出现 3 次、**`hard-confirm-2` 出现 0 次**——即极高风险操作事实上**无法被人工放行**;
- 用户实测现象一致:只弹一次窗,第 1 次批准被立刻当成拒绝,之后不再有第 2 次。

**v0.3.0 替换方案**:极高风险不再依赖模型行为,改为**批准密码**——拦截后登记待批准请求,用户在设置页(或 `/dsh-permission-matrix/approve` 批准页)输入密码才签发一次性令牌放行;没有密码就永远拒绝。设置页新增「极高风险批准密码」区块(设置 / 修改 / 清除密码、待批准请求列表、授权下一次、批准有效期)。

**破坏性变更**:`hardConfirmWindowMs` 由 `approvalPasswordTtlMs` 取代;极高风险 `ask` 档不再产生人工审批弹窗(改走密码闸门);审计 `outcome` 用 `password-required` / `password-approved` 取代 `hard-ask-1` / `hard-confirm-2`。

### v0.3.1:密码批准从「极高风险专属」升级为**四档通用方式**

- 「需批准密码」不再是极高风险专属:低 / 中 / 高 / 极高**任一档**都能选 `password`;
- 入口从「去设置页批准」升级为**插件自己的密码弹窗**(注册进 `shell.overlay`,浮在整个应用之上):挂起的调用**当场放行**,不再需要模型重试;设置页区块与 `/dsh-permission-matrix/approve` 批准页保留为等价入口;
- 命名与配置键去「hard」化:`hardApproval.js` → `password-approval.js`、`hardApprovalPasswordHash` → `approvalPasswordHash`、`hardApprovalTtlMs` → `approvalPasswordTtlMs`;旧键**保留兼容读取**并会在下次设置密码时自动迁移,已设口令不受影响;
- `ask` 与 `password` 明确区分:`ask` 仍是浏览器审批弹窗(点同意即放行),`password` 必须知道口令;极高风险档两者等价。

## 参考与致谢

本插件的设计参考了以下三个社区插件(思路借鉴 + 取舍改进,**代码为独立实现**):

### 1. [dsh-auto-classifier](https://github.com/nanmicoder/dsh-auto-classifier) — 主要参考

- **借鉴**:单点 `auto` 预设的定位(低风险放行 / 危险拦截 / 沙箱升级自动裁决)、`tools/pre-execute` + `approval/request` 双钩子 + `{prepend:true}` 抢占、HARD/SOFT 风险分级、`Tool(pattern)` 规则语法、字段投影(命令类只扫 `command/code`、路径类只扫 `file_path`)、工作区内结构放行、LLM 裁判两阶段(快速过滤 + 思考复审)、拒绝日志与 denial 上限、Git 快照。
- **改进**:把「单点 auto」升级为 **3 沙箱 × 4 审批 = 9 个可组合预设**;风险分级从 2 档细化为**低/中/高 + 极高**,且四档**各自可配**(极高档只允许拒绝 / 转人工(需批准密码));新增执行面识别以消除"提及即拦截";新增全局默认 + LLM 机器人默认两个维度。
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
