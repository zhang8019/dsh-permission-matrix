/**
 * dsh-permission-matrix — DSH 权限矩阵插件（host 半侧）。
 *
 * 提供 3 沙箱模式 × 4 审批策略的 9 个组合预设（预设表由 cordis.patch.yml 注入），
 * 取代 dsh-auto-classifier 的单点 `auto` 预设；并支持「全局默认预设」与
 * 「LLM 机器人默认预设」两个维度。
 *
 * 接管方式：预设表 approval 只有 ask/never，因此「自动同意 / 自动风险审批」档
 * 在预设表里写 `ask`，由本插件在审批瀑布前（prepend）按当前会话预设分流：
 *   - `auto-allow`：硬拒绝保护 + 其余一律 `allowed-once`
 *   - `classify`  ：规则 → LLM 裁判 → 中档策略（拒绝 / 同意 / 转人工）
 * 其余预设（人工审批 / 自动拒绝）本插件全程 `next()`，行为与 DSH 原生一致。
 *
 * @module dsh-permission-matrix
 */

import Schema from '@deepseek-ai/schemastery'
import { PRESETS, PRESET_IDS, TAKEOVER_DEFAULT } from './presets.js'
import { makePresetRouter } from './preset-router.js'
import { applyJudgeVerdict, applyRiskPolicy, classifyByRules } from './decide.js'
import { ALLOW_RULES, HARD_DENY_RULES, projectTarget } from './rules.js'
import { makeJudge } from './judge.js'
import { makeAudit } from './audit.js'
import { makeSnapshot } from './snapshot.js'
import { makeRobotDefaults } from './robot-presets.js'
import { installSettings, registerRoutes } from './settings.js'

/** 插件名（Cordis 要求）。 */
export const name = 'permission-matrix'

/** 依赖服务：工具注册表（pre-execute 钩子所在）。其余服务用 ctx.get 可选获取。 */
export const inject = ['tools']

/** 本插件发起的「转人工」审批请求的 reason 前缀（防回环标记）。 */
const HUMAN_TAG = '[pm]'

/** 插件配置（Schemastery；所有可调参数走这里，不硬编码）。 */
export const Config = Schema.object({
  /** 总开关。 */
  enabled: Schema.boolean().default(true),
  /**
   * 预设 id → 审批档（`auto-allow` / `classify`）。
   * 未列出的预设本插件全程 next()，行为与 DSH 原生一致。
   */
  takeover: Schema.dict(Schema.string()).default({ ...TAKEOVER_DEFAULT }),
  /**
   * 三档风险策略 + 极高风险档：
   *  - low / medium / high 各自可选「放行 / 拒绝 / 转人工」；
   *  - hard（极高风险）只允许「拒绝 / 转人工」——配置为 ask 时走双重人工确认
   *    （同一操作须人工同意两次：第 1 次同意记录后返回拒绝，第 2 次相同调用才放行）。
   */
  riskPolicies: Schema.object({
    low: Schema.union(['allow', 'deny', 'ask']).default('allow'),
    medium: Schema.union(['allow', 'deny', 'ask']).default('deny'),
    high: Schema.union(['allow', 'deny', 'ask']).default('deny'),
    hard: Schema.union(['deny', 'ask']).default('deny'),
  }).default({ low: 'allow', medium: 'deny', high: 'deny', hard: 'deny' }),
  /** 极高风险双重确认的窗口（毫秒）：第 1 次人工同意后，在此窗口内相同调用第 2 次放行。 */
  hardConfirmWindowMs: Schema.number().default(120000),
  /** LLM 裁判开关。 */
  llmJudge: Schema.boolean().default(true),
  /** LLM 裁判模型（留空 = 跟随当前会话模型）。 */
  judgeProvider: Schema.string().default(''),
  judgeModel: Schema.string().default(''),
  /** LLM 裁判阶段：both（快速过滤 + 思考复审）/ fast / thinking。 */
  judgeStages: Schema.union(['both', 'fast', 'thinking']).default('both'),
  /** 自动同意档的硬拒绝保护（极高风险不自动放行）。 */
  autoAllowHardGuard: Schema.boolean().default(true),
  /** 机器人默认预设（社交渠道会话）。 */
  robotDefaultPreset: Schema.string().default('fa-auto'),
  /** 机器人会话工作区（绝对路径列表）。 */
  robotWorkspaces: Schema.array(Schema.string()).default([]),
  /** Git 快照开关与节流。 */
  gitSnapshot: Schema.boolean().default(true),
  gitSnapshotIntervalMs: Schema.number().default(30000),
  /** 审计日志。 */
  auditLog: Schema.boolean().default(true),
  auditFile: Schema.string().default(''),
})

/**
 * 装配插件。
 * @param {import('@deepseek-ai/cordis').Context} ctx - 插件上下文。
 * @param {object} config - 已校验的配置。
 */
export function apply(ctx, config) {
  if (!config.enabled) {
    ctx.logger.info('permission-matrix: disabled by config')
    return
  }

  // ── 配置自检（响亮失败，不静默） ──────────────────────────────────────────
  const unknown = Object.keys(config.takeover).filter((id) => !PRESET_IDS.includes(id))
  if (unknown.length > 0) {
    throw new Error(`permission-matrix: takeover names unknown preset(s): ${unknown.join(', ')} (known: ${PRESET_IDS.join(', ')})`)
  }
  const invalidTier = Object.entries(config.takeover).filter(([, tier]) => tier !== 'auto-allow' && tier !== 'classify')
  if (invalidTier.length > 0) {
    throw new Error(`permission-matrix: takeover tier must be "auto-allow" or "classify", got ${JSON.stringify(Object.fromEntries(invalidTier))}`)
  }
  if (!PRESET_IDS.includes(config.robotDefaultPreset)) {
    throw new Error(`permission-matrix: robotDefaultPreset "${config.robotDefaultPreset}" is not a known preset (known: ${PRESET_IDS.join(', ')})`)
  }

  // ── 配置源：settings 层可热覆盖 composition 层 ──────────────────────────
  let getConfig = () => config
  installSettings(ctx, config, Config, (getter) => {
    getConfig = getter
  })

  const router = makePresetRouter(ctx, () => getConfig())
  const judge = makeJudge(ctx, () => getConfig())
  const audit = makeAudit(config)
  const snapshot = makeSnapshot(config, ctx.logger)
  const robotDefaults = makeRobotDefaults(ctx, () => getConfig())
  registerRoutes(ctx, { getConfig: () => getConfig(), getAudit: () => audit })

  /** 防回环：本插件自己发起的「转人工」请求（session → Set<callId>），在 approval/request 中让位给其他应答者。 */
  const pendingHuman = new WeakMap()
  const markPending = (session, callId) => {
    if (session === undefined || callId === undefined) return
    let set = pendingHuman.get(session)
    if (set === undefined) {
      set = new Set()
      pendingHuman.set(session, set)
    }
    set.add(callId)
  }
  const takePending = (session, callId) => {
    const set = session === undefined ? undefined : pendingHuman.get(session)
    if (set === undefined || callId === undefined || !set.has(callId)) return false
    set.delete(callId)
    return true
  }

  // ── 极高风险「双重人工确认」状态机（riskPolicies.hard = 'ask' 时启用） ─────
  // 语义：同一操作须人工同意两次。第 1 次同意（approval/request 下游 allowed-once）
  // 只记录指纹并返回 rejected（本次不执行）；窗口内相同指纹的第 2 次调用直接放行。
  const hardAskRegs = new WeakMap() // session → Map<callId, {fingerprint, toolName}>
  const hardConfirmed = new Map() // sessionId → [{fingerprint, toolName, at}]
  const fingerprintOf = (exec) => `${exec.name}::${projectTarget(exec.name, exec.arguments).text.toLowerCase()}`
  const registerHardAsk = (session, callId, info) => {
    if (session === undefined || callId === undefined) return
    let map = hardAskRegs.get(session)
    if (map === undefined) {
      map = new Map()
      hardAskRegs.set(session, map)
    }
    map.set(callId, info)
  }
  const takeHardAsk = (session, callId) => {
    if (session === undefined) return null
    const map = hardAskRegs.get(session)
    if (map === undefined || callId === undefined) return null
    const info = map.get(callId)
    if (info === undefined) return null
    map.delete(callId)
    return info
  }
  const recordHardConfirm = (session, { fingerprint, toolName }) => {
    const key = String(session?.id ?? '')
    if (key === '') return
    const list = hardConfirmed.get(key) ?? []
    list.push({ fingerprint, toolName, at: Date.now() })
    hardConfirmed.set(key, list)
  }
  const takeHardConfirm = (session, fingerprint) => {
    const key = String(session?.id ?? '')
    if (key === '') return false
    const list = hardConfirmed.get(key)
    if (list === undefined || list.length === 0) return false
    const windowMs = Math.max(0, Number(getConfig().hardConfirmWindowMs) || 0)
    const now = Date.now()
    const idx = list.findIndex((entry) => entry.fingerprint === fingerprint && now - entry.at < windowMs)
    if (idx === -1) return false
    list.splice(idx, 1)
    if (list.length === 0) hardConfirmed.delete(key)
    return true
  }

  /**
   * 规则层裁决（HARD → 区内放行 → ALLOW → null）。
   * @param {object} exec - 工具执行。
   * @returns {object | null} 裁决。
   */
  const ruleVerdictOf = (exec) => {
    const workspace = exec.agent?.session?.header?.cwd ?? ''
    return classifyByRules({ toolName: exec.name, args: exec.arguments, workspace })
  }

  /**
   * 在审批请求的 reason 文本上做规则匹配（审批请求没有工具参数）。
   * @param {string} text - reason 文本。
   * @returns {'deny' | 'allow' | null} 规则结论。
   */
  const ruleVerdictOfText = (text) => {
    const value = String(text ?? '')
    if (value === '') return null
    if (HARD_DENY_RULES.some((rule) => rule.test.test(value))) return 'deny'
    if (ALLOW_RULES.some((rule) => rule.test.test(value))) return 'allow'
    return null
  }

  const describe = (verdict) => `${verdict.rule}${verdict.note === undefined ? '' : `（${verdict.note}）`}`

  /**
   * 完整裁决：硬拒绝 → 高风险规则 → 低风险规则 → LLM 裁判 → 三档风险策略。
   * @param {object} exec - 工具执行。
   * @param {{presetId: string, tier: string}} route - 路由。
   * @returns {Promise<object>} 裁决（含 source）。
   */
  const decide = async (exec, route) => {
    const policies = getConfig().riskPolicies
    const byRule = ruleVerdictOf(exec)
    if (byRule !== null) {
      // 极高风险：默认拒绝；配置 ask 时转人工（双重确认在下方 ask 分支处理）
      if (byRule.risk === 'hard') return { ...applyRiskPolicy('hard', policies, byRule.rule), source: 'rule', note: byRule.note }
      // 高风险规则命中（非盘根递归删除 / git push）：按 riskPolicies.high 分派
      if (byRule.risk === 'high') return { ...applyRiskPolicy('high', policies, byRule.rule), source: 'rule', note: byRule.note }
      // 允许规则命中 / 工作区内结构放行 / 工作区内递归删除豁免 → 低风险
      return { ...applyRiskPolicy('low', policies, byRule.rule), source: 'rule', note: byRule.note }
    }

    if (route.tier === 'classify' && getConfig().llmJudge) {
      const target = projectTarget(exec.name, exec.arguments)
      const verdict = await judge({ toolName: exec.name, target: target.text, session: exec.agent?.session, signal: exec.signal })
      // allow → 低风险；deny → 高风险；unsure → 中风险
      return { ...applyJudgeVerdict(verdict, policies), source: 'judge' }
    }
    return { ...applyRiskPolicy('medium', policies, 'unmatched'), source: 'mid' }
  }

  // ── 钩子 1：工具预执行（allow / deny / ask） ──────────────────────────────
  ctx.on(
    'tools/pre-execute',
    async (exec, next) => {
      const session = exec.agent?.session
      const route = router.route(session)
      if (route === null) return next()

      try {
        let effective
        if (route.tier === 'auto-allow') {
          // 自动同意档：只保留硬拒绝保护，其余一律放行
          const byRule = ruleVerdictOf(exec)
          if (byRule === null || byRule.decision === 'allow') return next()
          // hard 配置 ask 时，自动同意档也走双重人工确认
          effective = byRule.risk === 'hard' && getConfig().riskPolicies.hard === 'ask'
            ? { ...applyRiskPolicy('hard', getConfig().riskPolicies, byRule.rule), source: 'rule', note: byRule.note }
            : { ...byRule, source: 'rule' }
        } else {
          effective = await decide(exec, route)
        }

        if (effective.decision === 'deny') {
          audit.write({
            sessionId: session?.id ?? null,
            preset: route.presetId,
            tool: exec.name,
            target: projectTarget(exec.name, exec.arguments).text.slice(0, 500),
            risk: effective.risk,
            rule: effective.rule,
            source: effective.source,
            decision: 'deny',
            outcome: 'blocked',
          })
          ctx.logger.info(`permission-matrix: deny ${exec.name} (${effective.risk}, ${effective.rule}, ${effective.source}) preset=${route.presetId}`)
          return {
            kind: 'deny',
            reason: `permission-matrix: ${exec.name} 被拒绝（${describe(effective)}）。这是策略裁决，不是沙箱错误；请换用其他方式，或请用户调整权限预设。`,
          }
        }

        if (effective.decision === 'ask') {
          // 极高风险双重确认：窗口内相同指纹的第 2 次调用直接放行
          if (effective.risk === 'hard' && takeHardConfirm(session, fingerprintOf(exec))) {
            audit.write({
              sessionId: session?.id ?? null,
              preset: route.presetId,
              tool: exec.name,
              target: projectTarget(exec.name, exec.arguments).text.slice(0, 500),
              risk: effective.risk,
              rule: effective.rule,
              source: effective.source,
              decision: 'allow',
              outcome: 'hard-confirm-2',
            })
            ctx.logger.info(`permission-matrix: allow ${exec.name} (${effective.rule}, double-confirmed) preset=${route.presetId}`)
            return next()
          }
          markPending(session, exec.callId)
          if (effective.risk === 'hard') registerHardAsk(session, exec.callId, { fingerprint: fingerprintOf(exec), toolName: exec.name })
          audit.write({
            sessionId: session?.id ?? null,
            preset: route.presetId,
            tool: exec.name,
            target: projectTarget(exec.name, exec.arguments).text.slice(0, 500),
            risk: effective.risk,
            rule: effective.rule,
            source: effective.source,
            decision: 'ask',
            outcome: effective.risk === 'hard' ? 'hard-ask-1' : 'escalated-to-human',
          })
          ctx.logger.info(`permission-matrix: ask ${exec.name} (${effective.rule}, ${effective.source}) preset=${route.presetId}`)
          const hint = effective.risk === 'hard'
            ? '极高风险操作需双重人工确认：第 1 次同意仅登记，本调用仍将被拒绝，请再次发起相同操作完成第 2 次确认后才会执行。'
            : '需人工确认'
          return { kind: 'ask', reason: `${HUMAN_TAG} ${hint}：${exec.name}（${describe(effective)}）` }
        }

        audit.write({
          sessionId: session?.id ?? null,
          preset: route.presetId,
          tool: exec.name,
          target: projectTarget(exec.name, exec.arguments).text.slice(0, 500),
          risk: effective.risk,
          rule: effective.rule,
          source: effective.source,
          decision: 'allow',
          outcome: 'passed',
        })
        return next()
      } catch (error) {
        ctx.logger.warn(`permission-matrix: pre-execute error: ${String(error?.message ?? error)}`)
        return next()
      }
    },
    { prepend: true },
  )

  // ── 钩子 2：审批请求（allowed-once / rejected / 转人工） ──────────────────
  ctx.on(
    'approval/request',
    async (req, next) => {
      if (req.signal?.aborted === true) return 'cancelled'

      const session = req.agent?.session
      const route = router.route(session)
      if (route === null) return next()

      // 防回环：本插件自己发起的转人工请求，交给浏览器/其他应答者
      if (takePending(session, req.callId) || String(req.reason ?? '').startsWith(HUMAN_TAG)) {
        const firstAsk = takeHardAsk(session, req.callId)
        const downstream = await next()
        // 极高风险双重确认：下游（用户）第 1 次同意 → 只记录指纹，本次仍拒绝执行，
        // 等窗口内相同调用第 2 次放行（pre-execute 的 takeHardConfirm 分支）。
        if (firstAsk !== null && downstream === 'allowed-once') {
          recordHardConfirm(session, firstAsk)
          audit.write({
            sessionId: session?.id ?? null,
            preset: route.presetId,
            tool: req.toolName,
            risk: 'hard',
            rule: 'hard:double-confirm',
            decision: 'ask',
            outcome: 'hard-confirm-1',
          })
          ctx.logger.info(`permission-matrix: double-confirm recorded for ${req.toolName} (${firstAsk.toolName}); ${firstAsk.fingerprint}`)
          return 'rejected'
        }
        return downstream
      }

      try {
        const textVerdict = ruleVerdictOfText(req.reason)

        if (route.tier === 'auto-allow') {
          if (getConfig().autoAllowHardGuard && textVerdict === 'deny') {
            audit.write({ sessionId: session?.id ?? null, preset: route.presetId, tool: req.toolName, risk: 'hard', rule: 'auto-allow:hard-guard', decision: 'reject', outcome: 'blocked' })
            ctx.logger.info(`permission-matrix: reject ${req.toolName} (hard guard) preset=${route.presetId}`)
            return 'rejected'
          }
          await snapshot(session, `auto-allow ${req.toolName}`)
          audit.write({ sessionId: session?.id ?? null, preset: route.presetId, tool: req.toolName, risk: 'medium', rule: 'auto-allow', decision: 'allow', outcome: 'allowed-once' })
          ctx.logger.info(`permission-matrix: auto-allow ${req.toolName} preset=${route.presetId}`)
          return 'allowed-once'
        }

        // classify 档
        if (textVerdict === 'deny') {
          audit.write({ sessionId: session?.id ?? null, preset: route.presetId, tool: req.toolName, risk: 'hard', rule: 'approval:hard', decision: 'reject', outcome: 'blocked' })
          return 'rejected'
        }
        if (textVerdict === 'allow') {
          await snapshot(session, `allow ${req.toolName}`)
          audit.write({ sessionId: session?.id ?? null, preset: route.presetId, tool: req.toolName, risk: 'low', rule: 'approval:allow', decision: 'allow', outcome: 'allowed-once' })
          return 'allowed-once'
        }

        const mid = applyRiskPolicy('medium', getConfig().riskPolicies, 'approval')
        audit.write({
          sessionId: session?.id ?? null,
          preset: route.presetId,
          tool: req.toolName,
          risk: mid.risk,
          rule: mid.rule,
          decision: mid.decision,
          outcome: mid.decision === 'ask' ? 'escalated-to-human' : mid.decision === 'allow' ? 'allowed-once' : 'blocked',
        })
        ctx.logger.info(`permission-matrix: ${mid.decision} ${req.toolName} (${mid.rule}) preset=${route.presetId}`)
        if (mid.decision === 'allow') {
          await snapshot(session, `mid-allow ${req.toolName}`)
          return 'allowed-once'
        }
        if (mid.decision === 'deny') return 'rejected'
        return next()
      } catch (error) {
        ctx.logger.warn(`permission-matrix: approval/request error: ${String(error?.message ?? error)}`)
        return next()
      }
    },
    { prepend: true },
  )

  // ── 钩子 3：会话创建 → 机器人默认预设 ────────────────────────────────────
  ctx.on('session/created', (session) => {
    try {
      robotDefaults.applyTo(session)
    } catch (error) {
      ctx.logger.warn(`permission-matrix: robot preset failed: ${String(error?.message ?? error)}`)
    }
  })

  ctx.logger.info(
    `permission-matrix: loaded ${PRESETS.length} presets; takeover=${JSON.stringify(config.takeover)}; riskPolicies=${JSON.stringify(config.riskPolicies)}; llmJudge=${config.llmJudge}; robotWorkspaces=${config.robotWorkspaces.length}`,
  )
}
