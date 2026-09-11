## v0.3.2 — 拼接/动态执行绕过修复 + 密码批准全面落地

从 v0.2.0 升级请重点看第 2 节（**破坏性变更**：极高风险的处理方式变了）。

### 1. 修复：命令拼接 / 动态执行绕过（安全）

此前 README 记为「已知限制（未修）」，实测确认不仅存在，同族漏拦更多：

```powershell
$p1='Remove-'; $p2='Item -Recurse -Force C:\'; & $p1$p2   # 修前：放行
$c='diskpart'; & $c                                        # 修前：放行
$x='shutdown /s'; iex $x                                    # 修前：放行
$cmd='net user hacker P@ss /add'; Invoke-Expression $cmd    # 修前：放行
```

根因：`executionSurface()` 会剥掉引号与变量赋值行，拼接写法下「命令面」什么都不剩，
而这些危险动词所在规则恰好都带 `surface:true`，于是全部失明。

修复方式：

- 检测到**动态执行形态**（`& $var` / `. $var` / `iex $var` / 相邻变量 `$a$b`）时，
  把**引号内的字符串当真实命令再跑一遍 HARD 规则**；
- 识别被拆开的 cmdlet 动词片段（`'Remove-'` 这类「动词 + 连字符结尾」）→ `hard:concat-fragment`；
- 该检查**只在出现动态执行形态时**触发，因此 `Write-Host 'rm -rf /'` 这类纯文案不受牵连
  —— 顺带修掉了此前「文案里提到危险词就被判 hard」的**误拦**（纯输出 cmdlet 现按执行面匹配）；
- 单独出现的 `& $someExe --version` 不硬拒绝，落到高风险规则 `high:dyn-call`（默认 deny，可配 `ask` / `password`）。

残余风险（未堵死）：多层间接（数组/哈希表/`$(...)` 拼接、`[scriptblock]::Create`、Base64 后 `iex`）仍可能绕过静态分析，依赖沙箱层与 LLM 裁判兜底。

### 2. 破坏性变更：极高风险从「双重人工确认」改为「密码批准」

v0.2 的「双重人工确认」要求模型在窗口内**原样重发同一条命令**才能完成第 2 次放行；
实测审计 1064 条记录里 `hard-confirm-1` 出现 3 次、**`hard-confirm-2` 出现 0 次**
——极高风险操作事实上无法被人工放行。

现在改为**密码批准**：操作被挂起（不失败），由插件的密码弹窗/设置页要求输入批准密码，
输对了**当场执行**（无需模型重试），输错或超时按拒绝处理。未设置密码 ⇒ 一律拒绝。

- 配置键：`hardConfirmWindowMs` → `approvalPasswordTtlMs`（旧键保留兼容读取，已设口令不丢）；
- 审计 `outcome`：`hard-ask-1` / `hard-confirm-2` → `password-required` / `password-approved` / `password-timeout` / `password-declined` / `password-cancelled`。

### 3. 「密码批准」是四档通用的审批方式

低 / 中 / 高 / 极高**任一档**都能把策略配成 `password`，与「放行 / 拒绝 / 转人工」并列：

- `ask`（转人工）= 浏览器审批弹窗，点一下「同意」即放行；
- `password`（密码批准）= 挂起等密码，**必须知道口令**，不会被"多点几次同意"绕过；
- 极高风险档两者等价（都走密码批准）。

### 4. GUI 密码弹窗（新增）

原生审批弹窗无法承载输入框，因此注册官方 `shell.overlay` 槽位自绘浮层：
出现待批准请求时自动弹出，输入密码点「批准并立即放行」→ 被挂起的调用当场执行。
设置页「批准密码」区块与 `/dsh-permission-matrix/approve` 批准页保留为等价入口。

### 5. 其它

- 命名去 hard 化：`hard-approval.js` → `password-approval.js`，配置键与路由同步改名；
- 测试 69 条全过（新增拼接绕过、纯输出文案不误伤、动态调用落高风险档、中风险档密码批准端到端等用例）。

---

**安装**

```sh
dsh plugin --profile <profile> add zhang8019/dsh-permission-matrix
```

或使用下方预构建 tarball。
