/**
 * 决策核心：纯函数、无 I/O、可单测。
 *
 * 判定顺序（与设计说明书 §6.1 一致）：
 *   1. HARD（极高风险）→ `deny`（人工也不能批准）
 *   2. 工作区内结构放行（write/edit/read 且目标在会话工作区内，受保护目标除外）→ `allow`
 *   3. ALLOW 规则 → `allow`
 *   4. 返回 `null`：交给调用方跑 LLM 裁判 / 中档策略
 *
 * @module dsh-permission-matrix/decide
 */

import path from 'node:path'
import { ALLOW_RULES, HARD_DENY_RULES, PROTECTED_TARGETS, projectTarget } from './rules.js'

/** 决策结果的风险级。 */
export const RISK = Object.freeze({ LOW: 'low', MEDIUM: 'medium', HARD: 'hard' })

/** 命令类工具里「会写文件系统」的命令前缀（用于收窄系统目录判定）。 */
const WRITE_COMMAND_PATTERN = /^\s*(copy|move|remove|rename|del|erase|set-content|add-content|clear-content|out-file|new-item|mkdir|md|attrib|icacls|takeown)/i

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
 * @param {string} target - 目标路径。
 * @returns {boolean} 是否受保护。
 */
export function isProtected(target, toolName) {
  const value = String(target ?? '')
  // 例外：本插件自己的审计目录只放裁决日志（不含密钥），允许 `read` 读取，
  // 否则插件会拦住对自己产物的自检；写入仍然拦截。
  if (toolName === 'read' && /[\\/]\.dsh[\\/]permission-matrix[\\/]/i.test(value)) return false
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

/**
 * 规则层裁决。返回 `null` 表示规则未命中，需上层继续（LLM 裁判 / 中档策略）。
 * @param {object} input - 输入。
 * @param {string} input.toolName - 工具名。
 * @param {object} input.args - 工具参数。
 * @param {string} input.workspace - 会话工作区。
 * @returns {{decision: 'allow' | 'deny', risk: string, rule: string, note?: string} | null} 裁决，或 null。
 */
export function classifyByRules({ toolName, args, workspace }) {
  const target = projectTarget(toolName, args)

  // 1) HARD —— 最高优先，任何策略都不能推翻
  if (target.text !== '') {
    for (const rule of HARD_DENY_RULES) {
      // `hard:protected-path`（系统目录）判定收窄：
      //  - 路径类工具（write/edit）一律判定；
      //  - 命令类工具只有「写命令」才判定——`Get-Content 'C:\Program Files\…'`
      //    是读取（如查看插件源码），此前被误判为「系统目录写入」（2026-09-09 实测）。
      if (rule.id === 'hard:protected-path' && target.kind !== 'path' && !WRITE_COMMAND_PATTERN.test(target.text)) continue
      if (rule.test.test(target.text)) {
        return { decision: 'deny', risk: RISK.HARD, rule: rule.id, note: rule.note }
      }
    }
  }

  // 2) 工作区内结构放行（仅路径类工具）
  if (target.kind === 'path' && target.text !== '') {
    const resolved = resolveTarget(target.text, workspace)
    if (isProtected(resolved, toolName)) {
      return { decision: 'deny', risk: RISK.HARD, rule: 'hard:protected-target', note: '受保护目标（配置/凭据/git 元数据）' }
    }
    if (isInside(resolved, workspace)) {
      return { decision: 'allow', risk: RISK.LOW, rule: 'allow:in-workspace', note: '目标在工作区内' }
    }
  }

  // 3) ALLOW 规则
  if (target.text !== '') {
    for (const rule of ALLOW_RULES) {
      if (rule.test.test(target.text)) {
        return { decision: 'allow', risk: RISK.LOW, rule: rule.id, note: rule.note }
      }
    }
  }

  // 4) 未命中
  return null
}

/**
 * 三档风险策略：低 / 中 / 高 各自可配（放行 / 拒绝 / 转人工）。
 * 极高风险（`hard`）不在此表内——它固定拒绝，任何策略都不能推翻。
 *
 * 默认值刻意保守：低风险放行、中风险与高风险拒绝。
 * @type {Readonly<{low: string, medium: string, high: string}>}
 */
export const DEFAULT_RISK_POLICIES = Object.freeze({ low: 'allow', medium: 'deny', high: 'deny' })

/** 归一化一条策略值（未知值一律按最保守的拒绝处理）。 */
function normalizePolicy(value) {
  return value === 'allow' || value === 'ask' ? value : 'deny'
}

/**
 * 按风险级别应用策略。
 * @param {'low' | 'medium' | 'high' | 'hard'} level - 风险级别。
 * @param {{low?: string, medium?: string, high?: string}} policies - 三档策略。
 * @param {string} rule - 触发该策略的规则标签（写审计）。
 * @returns {{decision: 'deny' | 'allow' | 'ask', risk: string, rule: string, note?: string}} 裁决。
 */
export function applyRiskPolicy(level, policies, rule = 'risk-policy') {
  if (level === 'hard') {
    return { decision: 'deny', risk: 'hard', rule: 'hard-boundary', note: '极高风险固定拒绝（人工也不能批准）' }
  }
  const policy = normalizePolicy(policies?.[level])
  const decision = policy === 'allow' ? 'allow' : policy === 'ask' ? 'ask' : 'deny'
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
