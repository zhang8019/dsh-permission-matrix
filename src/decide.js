/**
 * 决策核心：纯函数、无 I/O、可单测。
 *
 * 判定顺序（与设计说明书 §6.1 一致）：
 *   1. HARD（极高风险）→ `deny`（默认）或 `password`（密码批准闸门，见 index.js / password-approval.js）
 *   2. HIGH（高风险）→ `riskPolicies.high` 策略；递归删除对工作区内路径豁免
 *   3. 工作区内结构放行（write/edit/read 且目标在会话工作区内，受保护目标除外）→ `allow`
 *   4. ALLOW 规则 → `allow`
 *   5. 返回 `null`：交给调用方跑 LLM 裁判 / 中档策略
 *
 * @module dsh-permission-matrix/decide
 */

import path from 'node:path'
import { ALLOW_RULES, executionSurface, HARD_DENY_RULES, HIGH_RISK_RULES, PROTECTED_TARGETS, projectTarget, READ_PATH_TOOLS } from './rules.js'

/** 决策结果的风险级。 */
export const RISK = Object.freeze({ LOW: 'low', MEDIUM: 'medium', HIGH: 'high', HARD: 'hard' })

/** 命令类工具里「会写文件系统」的命令前缀（用于收窄系统目录/配置判定）。 */
const WRITE_COMMAND_PATTERN = /^\s*(copy|move|remove|rmdir|rd|rename|del|erase|set-content|add-content|clear-content|out-file|new-item|mkdir|md|attrib|icacls|takeown)/i

/**
 * Windows 大小写不敏感、路径分隔符归一化的比较键。
 * @param {string} value - 路径。
 * @returns {string} 比较键。
 */
function pathKey(value) {
  return path.resolve(value).replace(/[\\/]+$/, '').toLowerCase()
}

/**
 * 目标是否位于工作区内（含相等）。
 * @param {string} target - 已解析的目标路径。
 * @param {string} workspace - 会话工作区。
 * @returns {boolean} 是否在区内。
 */
export function isInside(target, workspace) {
  if (typeof target !== 'string' || target === '' || typeof workspace !== 'string' || workspace === '') return false
  const t = pathKey(target)
  const w = pathKey(workspace)
  return t === w || t.startsWith(`${w}${path.sep}`)
}

/**
 * 目标是否为受保护目标（即使在区内也不放行）。
 * 只读工具（read/read_image）读取 `.dsh` / `.git` 元数据（非凭据）放行——
 * 读取配置不是篡改（2026-09-09 实测 D 类误拦）；写工具依旧拦截。
 * @param {string} target - 目标路径。
 * @param {string} toolName - 工具名。
 * @returns {boolean} 是否受保护。
 */
export function isProtected(target, toolName) {
  const value = String(target ?? '')
  // 例外：本插件自己的审计目录只放裁决日志（不含密钥），允许 `read` 读取，
  // 否则插件会拦住对自己产物的自检；写入仍然拦截。
  if (toolName === 'read' && /[\\/]\.dsh[\\/]permission-matrix[\\/]/i.test(value)) return false
  // 只读工具读取 .dsh / .git 元数据（非凭据路径）→ 放行；凭据仍拦。
  if (READ_PATH_TOOLS.includes(toolName) && !/credentials|id_(rsa|ed25519)/i.test(value)) {
    if (/\.dsh[\\/]|\.git[\\/]/i.test(value)) return false
  }
  return PROTECTED_TARGETS.some((pattern) => pattern.test(value))
}

/**
 * 解析路径类工具的目标（相对路径按工作区解析）。
 * @param {string} raw - 原始 file_path。
 * @param {string} workspace - 会话工作区。
 * @returns {string} 绝对路径（词法归一化）。
 */
export function resolveTarget(raw, workspace) {
  const text = String(raw ?? '').trim()
  if (text === '') return ''
  if (path.isAbsolute(text)) return path.normalize(text)
  return path.resolve(workspace || process.cwd(), text)
}

/** 提取命令文本中第一个「路径状」token（绝对盘符 / 家目录 / 相对路径）。 */
export function firstDeleteTarget(text) {
  // 先去掉引号：路径常被引号包裹（含空格/特殊字符），如 rm -rf "./dist"、"C:\x"
  const value = String(text ?? '').replace(/["']/g, '')
  const abs = value.match(/[a-zA-Z]:[\\/][^\s;|&"']*/)
  if (abs) return abs[0].replace(/[\\/]+$/, '')
  const home = value.match(/(?:~|\$HOME)[\\/][^\s;|&"']*/i)
  if (home) return home[0].replace(/[\\/]+$/, '')
  const rel = value.match(/(?:^|[\s;|&])(?!-)([^\s;|&"'`]+[\\/][^\s;|&"'`]*)/)
  if (rel) return rel[1].replace(/[\\/]+$/, '')
  return ''
}

/**
 * 命令文本中的删除目标是否位于工作区内（用于 HIGH 递归删除豁免）。
 * @param {string} text - 命令原文（未剥离引号，路径常在引号内）。
 * @param {string} workspace - 会话工作区。
 * @returns {boolean} 目标是否在工作区内。
 */
export function isWorkspaceDelete(text, workspace) {
  const target = firstDeleteTarget(text)
  if (target === '') return false
  if (/^[a-zA-Z]:[\\/]/.test(target)) return isInside(path.resolve(target), workspace)
  if (/^~[\\/]|\$HOME/i.test(target)) return false // 家目录路径不算工作区
  const resolved = path.resolve(workspace, target)
  return isInside(resolved, workspace)
}

/**
 * 规则层裁决。返回 `null` 表示规则未命中，需上层继续（LLM 裁判 / 中档策略）。
 * @param {object} input - 输入。
 * @param {string} input.toolName - 工具名。
 * @param {object} input.args - 工具参数。
 * @param {string} input.workspace - 会话工作区。
 * @returns {{decision: 'allow' | 'deny' | 'ask', risk: string, rule: string, note?: string} | null} 裁决，或 null。
 */
export function classifyByRules({ toolName, args, workspace }) {
  const target = projectTarget(toolName, args)
  const surface = target.kind === 'command' ? executionSurface(target.text) : ''

  // 1) HARD —— 最高优先，任何 lower 档策略都不能推翻
  if (target.text !== '') {
    for (const rule of HARD_DENY_RULES) {
      const isReadOnlyPathTool = target.kind === 'path' && READ_PATH_TOOLS.includes(toolName)
      // `hard:protected-path`（系统目录）与 `hard:dsh-config`（DSH 配置）判定收窄：
      //  - 只读路径工具（read/read_image）读取系统文件/配置 → 放行（读取不是写入）；
      //  - 命令类工具只有「写命令」才判定——`Get-Content 'C:\Program Files\…'`
      //    或 `[IO.File]::ReadAllText(...settings.yaml)` 是读取（2026-09-09 实测误拦）。
      if ((rule.id === 'hard:protected-path' || rule.id === 'hard:dsh-config') && (isReadOnlyPathTool || (target.kind !== 'path' && !WRITE_COMMAND_PATTERN.test(target.text)))) continue
      const textFor = rule.surface === true ? surface : target.text
      if (rule.test.test(textFor)) {
        return { decision: 'deny', risk: RISK.HARD, rule: rule.id, note: rule.note }
      }
    }
  }

  // 1.5) 命令类「写命令」命中受保护目标（.dsh / git 元数据 / 凭据）→ 硬边界。
  //      此前 PROTECTED_TARGETS 只对路径类工具生效，命令类可绕过（2026-09-09 实测
  //      `New-Item ...\.dsh\...` 成功写入）。
  if (target.kind === 'command' && WRITE_COMMAND_PATTERN.test(target.text) && PROTECTED_TARGETS.some((pattern) => pattern.test(target.text))) {
    return { decision: 'deny', risk: RISK.HARD, rule: 'hard:protected-target', note: '受保护目标（配置/凭据/git 元数据）' }
  }

  // 2) HIGH —— 高风险，按 riskPolicies.high 分派；递归删除对工作区内路径豁免
  if (target.kind === 'command' && surface !== '') {
    for (const rule of HIGH_RISK_RULES) {
      if (rule.test.test(surface)) {
        if (isWorkspaceDelete(target.text, workspace)) {
          return { decision: 'allow', risk: RISK.LOW, rule: rule.id, note: '工作区内递归/批量删除豁免' }
        }
        return { decision: 'ask', risk: RISK.HIGH, rule: rule.id, note: rule.note }
      }
    }
  }

  // 3) 工作区内结构放行（仅路径类工具）
  if (target.kind === 'path' && target.text !== '') {
    const resolved = resolveTarget(target.text, workspace)
    if (isProtected(resolved, toolName)) {
      return { decision: 'deny', risk: RISK.HARD, rule: 'hard:protected-target', note: '受保护目标（配置/凭据/git 元数据）' }
    }
    if (isInside(resolved, workspace)) {
      return { decision: 'allow', risk: RISK.LOW, rule: 'allow:in-workspace', note: '目标在工作区内' }
    }
  }

  // 4) ALLOW 规则
  if (target.text !== '') {
    for (const rule of ALLOW_RULES) {
      if (rule.test.test(target.text)) {
        return { decision: 'allow', risk: RISK.LOW, rule: rule.id, note: rule.note }
      }
    }
  }

  // 5) 未命中
  return null
}

/**
 * 四档风险策略：低 / 中 / 高 / 硬 各自可配。
 *  - low / medium / high：allow（放行）/ deny（拒绝）/ ask（转人工弹窗）/ password（挂起等批准密码）；
 *  - hard（极高风险）：只允许 deny / ask / password —— ask 与 password 等价（都走批准密码闸门），
 *    配置为 allow 一律按最保守的 deny 处理（fail-closed）。
 *
 * `password` 与 `ask` 的区别：`ask` 交给浏览器人工审批弹窗（点「同意」即放行）；
 * `password` 由本插件挂起并弹**密码框**，只有输入正确口令才放行（见 index.js / password-approval.js）。
 *
 * 默认值刻意保守：低风险放行、中风险与高风险拒绝、极高风险拒绝。
 * @type {Readonly<{low: string, medium: string, high: string, hard: string}>}
 */
export const DEFAULT_RISK_POLICIES = Object.freeze({ low: 'allow', medium: 'deny', high: 'deny', hard: 'deny' })

/** 归一化一条策略值（未知值一律按最保守的拒绝处理）。 */
function normalizePolicy(value) {
  if (value === 'allow' || value === 'ask' || value === 'password') return value
  return 'deny'
}

/**
 * 按风险级别应用策略。
 * @param {'low' | 'medium' | 'high' | 'hard'} level - 风险级别。
 * @param {{low?: string, medium?: string, high?: string, hard?: string}} policies - 策略表。
 * @param {string} rule - 触发该策略的规则标签（写审计）。
 * @returns {{decision: 'deny' | 'allow' | 'ask' | 'password', risk: string, rule: string, note?: string}} 裁决。
 */
export function applyRiskPolicy(level, policies, rule = 'risk-policy') {
  if (level === 'hard') {
    // 极高风险不接受 allow；ask 与 password 都是「必须输批准密码」，其余一律拒绝。
    const configured = policies?.hard === 'ask' || policies?.hard === 'password'
    const decision = configured ? 'password' : 'deny'
    return {
      decision,
      risk: 'hard',
      rule: configured ? `${rule}:hard:password` : 'hard-boundary',
      note: configured ? '极高风险需批准密码才能放行' : '极高风险固定拒绝（人工也不能批准）',
    }
  }
  const policy = normalizePolicy(policies?.[level])
  // ask（转人工弹窗）与 password（挂起等密码）是两种不同处置，不能混为一谈。
  const decision = policy === 'allow' ? 'allow' : policy === 'deny' ? 'deny' : policy === 'ask' ? 'ask' : 'password'
  return { decision, risk: level, rule: `${rule}:${level}:${decision}` }
}

/**
 * 中档策略（兼容旧签名：规则未命中且裁判未决时如何处置）。
 * @param {'deny' | 'allow' | 'ask'} policy - 中档策略。
 * @param {string} rule - 触发该策略的规则标签（写审计）。
 * @returns {{decision: 'deny' | 'allow' | 'ask', risk: string, rule: string}} 裁决。
 */
export function applyMidPolicy(policy, rule = 'mid-policy') {
  switch (policy) {
    case 'allow':
      return { decision: 'allow', risk: RISK.MEDIUM, rule: `${rule}:allow` }
    case 'ask':
      return { decision: 'ask', risk: RISK.MEDIUM, rule: `${rule}:ask` }
    case 'deny':
    default:
      return { decision: 'deny', risk: RISK.MEDIUM, rule: `${rule}:deny` }
  }
}

/**
 * 把裁判结论映射为风险级别，再套用对应策略。
 * - 裁判 `allow` → 低风险；`deny` → 高风险；`unsure` → 中风险。
 * @param {'allow' | 'deny' | 'unsure'} verdict - 裁判结论。
 * @param {{low?: string, medium?: string, high?: string}} policies - 三档策略。
 * @param {string} rule - 裁判规则标签。
 * @returns {{decision: string, risk: string, rule: string}} 裁决。
 */
export function applyJudgeVerdict(verdict, policies, rule = 'judge') {
  if (verdict === 'allow') return applyRiskPolicy('low', policies, rule)
  if (verdict === 'deny') return applyRiskPolicy('high', policies, rule)
  return applyRiskPolicy('medium', policies, `${rule}:unsure`)
}
