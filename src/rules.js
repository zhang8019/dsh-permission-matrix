/**
 * 默认规则表与字段投影（决策核心的输入）。
 *
 * 清单来源：`dsh-auto-classifier` 的默认 deny/allow 表 + `dsh-yolo-mode` 的
 * dangerousPatterns，合并去重后按本插件的四段式使用：
 *   - HARD（极高风险）→ 默认 `deny`；可配置 `ask` 时走「批准密码」通道，
 *     拦截后须在设置页输入极高风险批准密码才放行一次（见 hard-approval.js）；
 *   - HIGH（高风险）→ 交给 `riskPolicies.high` 策略（默认 deny，可配 ask）；
 *   - ALLOW（低风险）→ `allow`；
 *   - 三者都未命中 → 交给 LLM 裁判 / 中档策略。
 *
 * 安全设计：
 *   1. 字段投影（防误伤）：命令类工具只扫 `command`/`code`，路径类只扫 `file_path`，
 *      审批请求只扫 `reason`——文件内容里提到危险词不算数。
 *   2. 执行面识别（`surface` 字段）：`surface: true` 的规则只匹配「执行面」文本
 *      （剥离行注释、变量赋值行、引号包裹字符串）——字符串字面量 / 注释 / 输出文本
 *      里「提及」危险关键词不再误伤；`surface` 缺省（路径类规则，如
 *      hard:rm-root / hard:credentials）保留原文，因为引号里可能就是被操作的真实路径。
 *   3. HARD / HIGH 清单是模块常量，settings 命名空间不暴露写路径（防止配置绕过硬边界）。
 *
 * @module dsh-permission-matrix/rules
 */

/** 命令类工具（扫命令文本）。 */
export const COMMAND_TOOLS = ['pwsh', 'bash', 'run_code']

/** 路径类工具（扫 file_path）。 */
export const PATH_TOOLS = ['write', 'edit', 'read', 'read_image']

/** 只读路径类工具（系统目录 / 配置读取豁免）。 */
export const READ_PATH_TOOLS = ['read', 'read_image']

/**
 * 硬拒绝（极高风险）。默认 `deny`；`riskPolicies.hard = 'ask'` 时走批准密码通道，
 * 不允许配置为 `allow`。命中即最高优先，任何 lower 档策略不能推翻。
 * @type {ReadonlyArray<{id: string, test: RegExp, note: string, surface?: boolean}>}
 */
export const HARD_DENY_RULES = Object.freeze([
  // ── 不可逆销毁 ────────────────────────────────────────────────────────────
  // 路径类规则：保留原文匹配（引号里就是被删的路径），`rm -rf "/"` 也必须拦。
  { id: 'hard:rm-root', test: /\brm\s+(-[a-z]*\s+)*-[a-z]*r[a-z]*f?\s+(-[a-z]+\s+)*["']?(\/|~|\$HOME)[\\/]?(\s|$|['"])/i, note: '递归删除根/家目录' },
  { id: 'hard:rm-root-win', test: /(remove-item|ri|rmdir|rd)\b(?=[^\n]*-recurse)(?=[^\n]*-force)(?=[^\n]*[a-z]:\\(\s|$|['"]))/i, note: '递归强删盘根目录(PowerShell)' },
  // cmd 风格盘根递归删除：rd/rmdir/del/erase + /s 或 /q + 盘根（2026-09-09 实测绕过）。
  { id: 'hard:rm-root-win-cmd', test: /(rmdir|rd|del|erase)\b(?=[^\n]*\/[sq]\b)(?=[^\n]*[a-z]:\\(\s|$|['"]))/i, note: '递归强删盘根目录(cmd)' },
  // 注意：不能用裸 `\bformat\b`——它会误伤 PowerShell 的 Format-Table / Format-List
  // 等无害 cmdlet（2026-09-09 实测误拦）。只有 `format <盘符>` 才是格式化。
  { id: 'hard:format-volume', test: /\bformat(\.com|\.exe)?\b\s+[a-z]:(\s|$|\/)/i, note: '格式化磁盘分区', surface: true },
  { id: 'hard:disk-tool', test: /\bdiskpart\b(?!\s+\/(\?|help))|\b(mkfs(\.\w+)?|fdisk)\b/i, note: '分区/文件系统工具', surface: true },
  { id: 'hard:dd-write', test: /\bdd\b[^\n]*\bof=\/dev\//i, note: 'dd 直写块设备', surface: true },
  // ── 引导 / 关机 / 系统服务 ────────────────────────────────────────────────
  // bcdedit /enum（只读枚举）放行，只有 /set 才是修改。
  { id: 'hard:boot', test: /\bbcdedit\b[^\n]*\/set\b|\b(bootrec|bootsect)\b/i, note: '引导配置修改', surface: true },
  // shutdown 需要真实开关（/?、裸 shutdown 是帮助/查询）；Stop/Restart-Computer
  // 只认命令动词位（Get-Help Stop-Computer 是帮助，不是执行）。
  { id: 'hard:power', test: /\bshutdown(\.exe)?\b[^\n]*[\/-](s|r|p|l|h|f|a|i|g|o)\b|(^|[;&|]\s*)(stop-computer|restart-computer)\b/i, note: '关机/重启', surface: true },
  // ── 账号 / ACL / 提权 ────────────────────────────────────────────────────
  // net user / net localgroup 裸列出是查询；只有带 /add /delete 才是管理写操作。
  { id: 'hard:account', test: /\bnet\s+(user|localgroup)\b[^\n]*\/(add|delete)\b/i, note: '账号/组管理', surface: true },
  // icacls 裸查 ACL、takeown /? 帮助应放行；带写开关才拦。
  { id: 'hard:acl', test: /\bicacls\b[^\n]*\/(grant|deny|remove|set|reset|inheritance|setintegritylevel)\b|\bcacls\b[^\n]*\/(g|d|p|e|r)\b|\btakeown\b[^\n]*\/f\b|\bset-acl\b/i, note: 'ACL/所有权变更', surface: true },
  // sudo/runas/psexec 只在命令动词位（Test-Path pm-sudo-notes.txt 是路径提及）。
  { id: 'hard:escalate', test: /(^|[;&|]\s*)(sudo|gsudo|runas|psexec)\b|start-process[^\n]*-verb\s+runas/i, note: '提权', surface: true },
  // ── 注册表 / 安全控制 / 持久化 ───────────────────────────────────────────
  { id: 'hard:registry', test: /\breg(\.exe)?\s+(add|delete|import|save|restore)\b|\bregedit(\.exe)?\s+\/s\b/i, note: '注册表写入', surface: true },
  { id: 'hard:firewall', test: /\bnetsh\b[^\n]*\b(advfirewall|firewall)\b|set-netfirewall/i, note: '防火墙修改', surface: true },
  { id: 'hard:av', test: /\bset-mppreference\b|add-mppreference|\bset-executionpolicy\b/i, note: '安全控制削弱', surface: true },
  // schtasks /query、sc query 是只读查询；只拦创建/变更/删除/运行类。
  { id: 'hard:persist', test: /\bschtasks\b[^\n]*\/(create|change|delete|run|end)\b|\bsc(\.exe)?\s+(create|delete|config)\b|\b(new-service|set-service|register-scheduledtask)\b/i, note: '计划任务/服务持久化', surface: true },
  // ── 动态执行 / 外部代码 ──────────────────────────────────────────────────
  { id: 'hard:pipe-exec', test: /\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(ba)?sh\b|\b(iwr|invoke-webrequest)\b[^\n|]*\|\s*(iex|invoke-expression)\b/i, note: '外部代码管道执行', surface: true },
  { id: 'hard:dyn-exec', test: /\b(invoke-expression|iex)\b[^\n]*(-encodedcommand|-enc\b|-c\b)|-encodedcommand\b/i, note: '动态/编码执行', surface: true },
  // ── 网络监听 ─────────────────────────────────────────────────────────────
  { id: 'hard:listen', test: /\b(nc|ncat|netcat)\b[^\n]*\s-l\b/i, note: '网络监听', surface: true },
  // ── git 破坏性远程操作 ───────────────────────────────────────────────────
  { id: 'hard:git-force', test: /\bgit\b[^\n]*\bpush\b[^\n]*(\s--force\b|\s-f\b|\s--force-with-lease\b)/i, note: 'git 强制推送', surface: true },
  // git reset --hard：丢弃工作区/历史，设计文档 §6.4 列为 HARD（2026-09-09 实测漏拦）。
  { id: 'hard:git-reset-hard', test: /\bgit\b[^\n]*\breset\b[^\n]*--hard\b/i, note: 'git 硬重置(丢弃改动)', surface: true },
  // ── 系统级包安装（项目级 npm/pnpm/yarn/bun 由 allow:pkg 放行，与这里区分） ──
  { id: 'hard:pkg-install-system', test: /\b(apt-get|apt|pip3?|winget|scoop|choco)\b[^\n]*\binstall\b/i, note: '系统级包安装', surface: true },
  // ── 凭据读取（收窄：只认精确凭据路径，不再匹配任意 `xxx_rsa`） ────────────
  { id: 'hard:credentials', test: /(\.ssh[\\/]id_(rsa|ed25519)\b|\.aws[\\/]credentials\b|\.dsh[\\/]\.credentials\.yaml\b|\.netrc\b)/i, note: '凭据/私钥文件' },
  // ── 受保护路径直写（只读工具豁免由 decide.js 处理） ───────────────────────
  { id: 'hard:protected-path', test: /[a-z]:[\\/](windows|program files( \(x86\))?|programdata)([\\/]|\s|$|['"])/i, note: '系统目录写入' },
  { id: 'hard:dsh-config', test: /\.dsh[\\/](settings\.yaml|cordis\.patch\.yml|profiles[\\/][^\\/\s]+[\\/]cordis\.patch\.yml)/i, note: 'DSH 配置篡改' },
])

/**
 * 高风险（默认 deny，可配 ask 转人工）。命中后由 `riskPolicies.high` 分派；
 * 其中「递归/批量删除」类对**工作区内路径豁免**（保持放行，不弹窗）。
 * @type {ReadonlyArray<{id: string, test: RegExp, note: string}>}
 */
export const HIGH_RISK_RULES = Object.freeze([
  // 盘根删除（rm -rf /、Remove-Item … C:\、cmd rd /s /q C:\）已被上方 HARD 抢先拦截。
  { id: 'high:rm-recursive-ps', test: /(remove-item|ri|rmdir|rd)\b(?=[^\n]*-(recurse|r)\b)/i, note: '非盘根递归删除(PowerShell)', surface: true },
  { id: 'high:rm-recursive-cmd', test: /\b(rmdir|rd|del|erase)\b[^\n]*\/[sq]\b/i, note: '非盘根递归/批量删除(cmd)', surface: true },
  { id: 'high:rm-recursive-unix', test: /\brm\s+(-[a-z]*\s+)*-rf\b/i, note: '非盘根递归删除(Unix)', surface: true },
  // 普通 git push（非 --force）设计文档列为 deny → 高风险档；--force 变体由 HARD 拦截。
  { id: 'high:git-push', test: /\bgit\b[^\n]*\bpush\b/i, note: 'git 推送(非强制)', surface: true },
])

/**
 * 允许（低风险）。命中即 `allow`（仅当 HARD / HIGH 未命中时）。
 * @type {ReadonlyArray<{id: string, test: RegExp, note: string}>}
 */
export const ALLOW_RULES = Object.freeze([
  { id: 'allow:git-read', test: /^\s*git\s+(status|log|diff|show|branch|remote\s+-v|rev-parse|describe)\b/i, note: 'git 只读' },
  { id: 'allow:git-local', test: /^\s*git\s+(add|commit|checkout\s+-b|switch|restore|stash|tag)\b/i, note: 'git 本地写' },
  { id: 'allow:pkg', test: /^\s*(npm|pnpm|yarn|bun)\s+(install|i|add|ci|run|test|build|exec|dlx)\b/i, note: '包管理器' },
  { id: 'allow:runtime', test: /^\s*(node|python|python3|py|deno|tsx|npx)\b/i, note: '语言运行时' },
  { id: 'allow:gh', test: /^\s*gh\s+/i, note: 'GitHub CLI' },
  { id: 'allow:dsh', test: /^\s*dsh(\.cmd)?\s+/i, note: 'DSH CLI' },
  { id: 'allow:pkgmgr-win', test: /^\s*(winget|scoop|choco)\s+(list|search|show|info)\b/i, note: 'Windows 包管理器查询' },
  { id: 'allow:ps-cmdlet', test: /^\s*(get|test|select|where|measure|resolve|split|join|convertto|convertfrom|format|out|write|echo|dir|ls|cat|type|find|sort|group|compare|import-csv|export-csv|copy|move|new-item|mkdir|set-content|add-content)-?[a-z]*\b/i, note: '常规 PowerShell cmdlet' },
])

/**
 * 受保护目标（工作区内结构放行时也要拦下的例外；命令类写命令同样适用）。
 * @type {ReadonlyArray<RegExp>}
 */
export const PROTECTED_TARGETS = Object.freeze([
  /\.dsh[\\/]/i,
  /\.git[\\/](config|hooks)/i,
  /\.credentials\.yaml$/i,
  /(^|[\\/])id_(rsa|ed25519)$/i,
])

/**
 * 归一化命令文本：剥掉环境变量前缀与重定向，降低误判。
 * @param {string} text - 原始命令文本。
 * @returns {string} 归一化后的文本。
 */
export function normalizeCommand(text) {
  return String(text ?? '')
    .replace(/\r/g, '\n')
    .replace(/^\s*[A-Za-z_][A-Za-z0-9_]*=\S+\s+/gm, '')
    .replace(/\s>\s*[^\s|&;]+/g, ' ')
    .trim()
}

/**
 * 执行面识别：剥离「非执行」部分后剩下的命令文本。
 *  - 行注释（PowerShell/bash 的 `#` 到行尾）；
 *  - 变量赋值行（`$x = "..."`，引号内只是数据不是执行）；
 *  - 引号包裹的字符串（`"..."` / `'...'`）。
 *
 * 注意：`surface: true` 的规则用本函数的结果匹配；路径类规则（rm-root /
 * credentials / protected-path / dsh-config）保留原文，因为引号里可能就是真实路径。
 * @param {string} text - 归一化命令文本。
 * @returns {string} 执行面文本。
 */
export function executionSurface(text) {
  return String(text ?? '')
    .replace(/\r/g, '\n')
    .replace(/#[^\n]*/g, ' ')
    .replace(/^\s*\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]*$/gm, ' ')
    .replace(/"[^"\n]*"/g, ' ')
    .replace(/'[^'\n]*'/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

/**
 * 从一次工具调用中提取「被审查的目标文本」（字段投影）。
 * @param {string} toolName - 工具名。
 * @param {object} args - 工具参数。
 * @returns {{kind: 'command' | 'path' | 'none', text: string}} 投影结果。
 */
export function projectTarget(toolName, args) {
  const name = String(toolName ?? '')
  const record = args !== null && typeof args === 'object' ? args : {}
  if (COMMAND_TOOLS.includes(name)) {
    const raw = typeof record.command === 'string' ? record.command : typeof record.code === 'string' ? record.code : ''
    return { kind: 'command', text: normalizeCommand(raw) }
  }
  if (PATH_TOOLS.includes(name)) {
    const raw = typeof record.file_path === 'string' ? record.file_path : typeof record.path === 'string' ? record.path : ''
    return { kind: 'path', text: raw.trim() }
  }
  return { kind: 'none', text: '' }
}
