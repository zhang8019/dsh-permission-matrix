/**
 * 默认规则表与字段投影（决策核心的输入）。
 *
 * 清单来源：`dsh-auto-classifier` 的默认 deny/allow 表 + `dsh-yolo-mode` 的
 * dangerousPatterns，合并去重后按本插件的三段式使用：
 *   - HARD（极高风险）→ 固定 `deny`，人工也不能批准，**只读不可编辑**；
 *   - ALLOW（低风险）→ `allow`；
 *   - 两者都未命中 → 交给 LLM 裁判 / 中档策略。
 *
 * 安全设计：
 *   1. 字段投影（防误伤）：命令类工具只扫 `command`/`code`，路径类只扫 `file_path`，
 *      审批请求只扫 `reason`——文件内容里提到危险词不算数。
 *   2. HARD 清单是模块常量，settings 命名空间不暴露写路径（防止配置绕过硬边界）。
 *
 * @module dsh-permission-matrix/rules
 */

/** 命令类工具（扫命令文本）。 */
export const COMMAND_TOOLS = ['pwsh', 'bash', 'run_code']

/** 路径类工具（扫 file_path）。 */
export const PATH_TOOLS = ['write', 'edit', 'read', 'read_image']

/**
 * 硬拒绝（极高风险）。命中即 `deny`，不接受人工批准，不可被 `allow` / `ask` 策略推翻。
 * @type {ReadonlyArray<{id: string, test: RegExp, note: string}>}
 */
export const HARD_DENY_RULES = Object.freeze([
  // ── 不可逆销毁 ────────────────────────────────────────────────────────────
  { id: 'hard:rm-root', test: /\brm\s+(-[a-z]*\s+)*-[a-z]*r[a-z]*f?\s+(-[a-z]+\s+)*(\/|~|\$HOME)[\\/]?(\s|$)/i, note: '递归删除根/家目录' },
  { id: 'hard:rm-root-win', test: /(remove-item|ri|rmdir|rd)\b(?=[^\n]*-recurse)(?=[^\n]*-force)(?=[^\n]*[a-z]:\\(\s|$|['"]))/i, note: '递归强删盘根目录' },
  // 注意：不能用裸 `\bformat\b`——它会误伤 PowerShell 的 Format-Table / Format-List
  // 等无害 cmdlet（2026-09-09 实测误拦）。只有 `format <盘符>` 才是格式化。
  { id: 'hard:format-volume', test: /\bformat(\.com|\.exe)?\b\s+[a-z]:(\s|$|\/)/i, note: '格式化磁盘分区' },
  { id: 'hard:disk-tool', test: /\b(diskpart|mkfs(\.\w+)?|fdisk)\b/i, note: '分区/文件系统工具' },
  { id: 'hard:dd-write', test: /\bdd\b[^\n]*\bof=\/dev\//i, note: 'dd 直写块设备' },
  // ── 引导 / 关机 / 系统服务 ────────────────────────────────────────────────
  { id: 'hard:boot', test: /\b(bcdedit|bootrec|bootsect)\b/i, note: '引导配置修改' },
  { id: 'hard:power', test: /\b(shutdown|restart-computer|stop-computer)\b/i, note: '关机/重启' },
  // ── 账号 / ACL / 提权 ────────────────────────────────────────────────────
  { id: 'hard:account', test: /\bnet\s+(user|localgroup)\b/i, note: '账号/组管理' },
  { id: 'hard:acl', test: /\b(icacls|takeown|set-acl|cacls)\b/i, note: 'ACL/所有权变更' },
  { id: 'hard:escalate', test: /\b(sudo|runas|gsudo|psexec)\b|start-process[^\n]*-verb\s+runas/i, note: '提权' },
  // ── 注册表 / 安全控制 / 持久化 ───────────────────────────────────────────
  { id: 'hard:registry', test: /\breg(\.exe)?\s+(add|delete|import|save|restore)\b|\bregedit(\.exe)?\s+\/s\b/i, note: '注册表写入' },
  { id: 'hard:firewall', test: /\bnetsh\b[^\n]*\b(advfirewall|firewall)\b|set-netfirewall/i, note: '防火墙修改' },
  { id: 'hard:av', test: /\bset-mppreference\b|add-mppreference|\bset-executionpolicy\b/i, note: '安全控制削弱' },
  { id: 'hard:persist', test: /\b(schtasks|sc(\.exe)?\s+(create|delete|config)|new-service|set-service|register-scheduledtask)\b/i, note: '计划任务/服务持久化' },
  // ── 动态执行 / 外部代码 ──────────────────────────────────────────────────
  { id: 'hard:pipe-exec', test: /\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(ba)?sh\b|\b(iwr|invoke-webrequest)\b[^\n|]*\|\s*(iex|invoke-expression)\b/i, note: '外部代码管道执行' },
  { id: 'hard:dyn-exec', test: /\b(invoke-expression|iex)\b[^\n]*(-encodedcommand|-enc\b|-c\b)|-encodedcommand\b/i, note: '动态/编码执行' },
  // ── 网络监听 ─────────────────────────────────────────────────────────────
  { id: 'hard:listen', test: /\b(nc|ncat|netcat)\b[^\n]*\s-l\b/i, note: '网络监听' },
  // ── git 破坏性远程操作 ───────────────────────────────────────────────────
  { id: 'hard:git-force', test: /\bgit\b[^\n]*\bpush\b[^\n]*(\s--force\b|\s-f\b|\s--force-with-lease\b)/i, note: 'git 强制推送' },
  // ── 凭据读取 ─────────────────────────────────────────────────────────────
  { id: 'hard:credentials', test: /(\.ssh[\\/](id_rsa|id_ed25519)\b|\.aws[\\/]credentials|\.dsh[\\/]\.credentials\.yaml|\.netrc\b|_rsa\b)/i, note: '凭据/私钥文件' },
  // ── 受保护路径直写 ───────────────────────────────────────────────────────
  { id: 'hard:protected-path', test: /[a-z]:[\\/](windows|program files( \(x86\))?|programdata)([\\/]|\s|$|['"])/i, note: '系统目录写入' },
  { id: 'hard:dsh-config', test: /\.dsh[\\/](settings\.yaml|cordis\.patch\.yml|profiles[\\/][^\\/\s]+[\\/]cordis\.patch\.yml)/i, note: 'DSH 配置篡改' },
])

/**
 * 允许（低风险）。命中即 `allow`（仅当 HARD 未命中时）。
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
 * 受保护目标（工作区内结构放行时也要拦下的例外）。
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
