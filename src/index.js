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
import { makePasswordApproval } from './password-approval.js'
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
   * 四档风险策略：
   *  - low / medium / high 各自可选「放行 / 拒绝 / 转人工 / 需批准密码」；
   *  - hard（极高风险）只允许「拒绝 / 需批准密码」——`ask` 与 `password` 等价，
   *    都走批准密码通道（未设置密码则一律拒绝，fail-closed）。
   *
   * `ask` = 浏览器人工审批弹窗（点同意即放行）；`password` = 挂起等本插件的密码框。
   */
  riskPolicies: Schema.object({
    low: Schema.union(['allow', 'deny', 'ask', 'password']).default('allow'),
    medium: Schema.union(['allow', 'deny', 'ask', 'password']).default('deny'),
    high: Schema.union(['allow', 'deny', 'ask', 'password']).default('deny'),
    hard: Schema.union(['deny', 'ask', 'password']).default('deny'),
  }).default({ low: 'allow', medium: 'deny', high: 'deny', hard: 'deny' }),
  /** 批准密码的 scrypt 哈希（设置页经专用路由写入；明文永不持久化）。 */
  approvalPasswordHash: Schema.string().default(''),
  /** 批准令牌/等待窗口（毫秒）：密码批准后放行一次，用后即焚。 */
  approvalPasswordTtlMs: Schema.number().default(300000),
  /** @deprecated v0.3.0 旧键（当时只服务极高风险）：仅保留兼容读取，写入一律用新键。 */
  hardApprovalPasswordHash: Schema.string().default(''),
  /** @deprecated v0.3.0 旧键：兼容读取。 */
  hardApprovalTtlMs: Schema.number().default(0),
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
  registerRoutes(ctx, { getConfig: () => getConfig(), getAudit: () => audit, getPasswordApproval: () => passwordApproval })

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

  // ── 「密码批准」通道（任一风险档配置为 password 时启用） ──────────────────
  // 语义：该风险档的操作一律挂起等密码；只有输入正确批准密码才放行（无密码 ⇒ 拒绝）。
  // v0.2 的「双重人工确认」依赖"模型在窗口内原样重发同一条命令"才能完成放行，
  // 而模型收到拒绝后通常改路径重试（指纹变化）——实测 1000+ 条审计里
  // `hard-confirm-2` 从未出现，等于那条路根本走不通。密码批准只取决于是否知道口令，
  // 与模型行为无关，并且不限于极高风险：低/中/高三档同样可以选它。
  const passwordApproval = makePasswordApproval(() => getConfig(), ctx.logger)
  const fingerprintOf = (exec) => `${exec.name}::${projectTarget(exec.name, exec.arguments).text.toLowerCase()}`

  /** 密码闸门等待登记：session → Map<callId, requestId>（pre-execute 登记，approval 层取用）。 */
  const passwordWaits = new WeakMap()
  const registerPasswordWait = (session, callId, requestId) => {
    if (session === undefined || callId === undefined) return
    let map = passwordWaits.get(session)
    if (map === undefined) {
      map = new Map()
      passwordWaits.set(session, map)
    }
    map.set(callId, requestId)
  }
  const takePasswordWait = (session, callId) => {
    if (session === undefined || callId === undefined) return null
    const map = passwordWaits.get(session)
    if (map === undefined) return null
    const value = map.get(callId)
    if (value === undefined) return null
    map.delete(callId)
    return value
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
      // 极高风险：默认拒绝；配置 ask 时转「批准密码」通道（在下方 ask 分支处理）
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

  /** 风险级别的中文名（提示文案用）。 */
  const riskLabel = (risk) => ({ low: '低风险', medium: '中风险', high: '高风险', hard: '极高风险' }[risk] ?? '该风险档')

  /**
   * 密码闸门挂起时的说明（模型会读到；真正的输入入口是 GUI 弹窗 / 批准页）。
   * @param {{exec: object, effective: object, requestId: string, passwordSet: boolean}} input - 输入。
   * @returns {string} 理由文本。
   */
  const passwordAskReason = ({ exec, effective, requestId, passwordSet }) => {
    const head = `${HUMAN_TAG} ${riskLabel(effective.risk)}操作需批准密码：${exec.name}（${describe(effective)}），本次调用已挂起等待放行。`
    if (!passwordSet) {
      return `${head}当前尚未设置「批准密码」，没有任何放行路径：请先在 GUI 的「设置 → 权限矩阵 → 批准密码」中设置密码，然后重新执行本操作。`
    }
    const seconds = Math.max(1, Math.round(passwordApproval.ttlMs() / 1000))
    return `${head}请在弹出的密码框（或「设置 → 权限矩阵 → 批准密码」、批准页 /dsh-permission-matrix/approve，请求号 ${requestId}）输入批准密码；输入正确后本次调用会立即放行，${seconds} 秒内未批准则按拒绝处理。这是策略裁决，不是沙箱错误。`
  }

  /**
   * 密码闸门（低 / 中 / 高 / 极高 任一档配置为 `password` 时启用）：
   * 命中令牌 → 放行；否则登记待批准请求并返回 `ask` —— 审批瀑布挂起等密码，
   * 密码正确即刻放行，超时/忽略则拒绝（没有"点几次同意就过"的路径）。
   * @param {{exec: object, session: object, route: object, effective: object, next: () => Promise<object>}} input - 输入。
   * @returns {Promise<object>} pre-execute 决策。
   */
  const passwordGate = async ({ exec, session, route, effective, next }) => {
    const target = projectTarget(exec.name, exec.arguments).text.slice(0, 500)
    const fingerprint = fingerprintOf(exec)

    const granted = passwordApproval.consume({ sessionId: session?.id, fingerprint })
    if (granted !== null) {
      audit.write({
        sessionId: session?.id ?? null,
        preset: route.presetId,
        tool: exec.name,
        target,
        risk: effective.risk,
        rule: effective.rule,
        source: 'password-gate',
        decision: 'allow',
        outcome: 'password-approved',
      })
      ctx.logger.info(`permission-matrix: allow ${exec.name} (${effective.risk}, password grant ${granted.id}/${granted.scope}) preset=${route.presetId}`)
      return next()
    }

    const registered = passwordApproval.registerRequest({
      sessionId: session?.id,
      fingerprint,
      toolName: exec.name,
      target,
      preset: route.presetId,
      rule: effective.rule,
      risk: effective.risk,
    })
    registerPasswordWait(session, exec.callId, registered.id)
    audit.write({
      sessionId: session?.id ?? null,
      preset: route.presetId,
      tool: exec.name,
      target,
      risk: effective.risk,
      rule: effective.rule,
      source: 'password-gate',
      decision: 'ask',
      outcome: 'password-required',
    })
    ctx.logger.info(`permission-matrix: ask ${exec.name} (${effective.risk}, waiting approval password, request=${registered.id}) preset=${route.presetId}`)
    return {
      kind: 'ask',
      reason: passwordAskReason({ exec, effective, requestId: registered.id, passwordSet: passwordApproval.passwordSet() }),
    }
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
          // 该风险档被显式配置为「需批准密码」（或极高风险的 ask）时，
          // 即使自动同意档也必须输密码——用户配的是硬边界，自动档不能绕过。
          const policies = getConfig().riskPolicies
          const policy = policies?.[byRule.risk]
          const passwordWanted = policy === 'password' || (byRule.risk === 'hard' && policy === 'ask')
          effective = passwordWanted
            ? { ...applyRiskPolicy(byRule.risk, policies, byRule.rule), source: 'rule', note: byRule.note }
            : { ...byRule, source: 'rule' }
        } else {
          effective = await decide(exec, route)
        }

        if (effective.decision === 'password') {
          // 需批准密码的风险档：挂起等密码（弹窗 / 批准页），密码是唯一放行凭据
          return await passwordGate({ exec, session, route, effective, next })
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
          markPending(session, exec.callId)
          audit.write({
            sessionId: session?.id ?? null,
            preset: route.presetId,
            tool: exec.name,
            target: projectTarget(exec.name, exec.arguments).text.slice(0, 500),
            risk: effective.risk,
            rule: effective.rule,
            source: effective.source,
            decision: 'ask',
            outcome: 'escalated-to-human',
          })
          ctx.logger.info(`permission-matrix: ask ${exec.name} (${effective.rule}, ${effective.source}) preset=${route.presetId}`)
          return { kind: 'ask', reason: `${HUMAN_TAG} 需人工确认：${exec.name}（${describe(effective)}）` }
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

      // 密码闸门挂起的调用：在这里等密码（GUI 弹窗 / 批准页 两条通道）。
      // 这里**不调 next()**，浏览器审批弹窗不参与——没有密码就没有放行路径；
      // 密码正确则本次调用立即放行，无需模型重试。
      const passwordRequestId = takePasswordWait(session, req.callId)
      if (passwordRequestId !== null) {
        const outcome = await passwordApproval.waitForDecision({
          requestId: passwordRequestId,
          timeoutMs: passwordApproval.ttlMs(),
          signal: req.signal,
        })
        if (outcome === 'allowed') {
          audit.write({ sessionId: session?.id ?? null, preset: route.presetId, tool: req.toolName, risk: req.risk ?? 'medium', rule: 'password-gate', source: 'password-gate', decision: 'allow', outcome: 'password-approved' })
          ctx.logger.info(`permission-matrix: allow ${req.toolName} (password approved in-flight) preset=${route.presetId}`)
          return 'allowed-once'
        }
        const outcomeTag = outcome === 'cancelled' ? 'password-cancelled' : outcome === 'timeout' ? 'password-timeout' : 'password-declined'
        audit.write({ sessionId: session?.id ?? null, preset: route.presetId, tool: req.toolName, risk: req.risk ?? 'medium', rule: 'password-gate', source: 'password-gate', decision: 'reject', outcome: outcomeTag })
        ctx.logger.info(`permission-matrix: reject ${req.toolName} (password ${outcome}) preset=${route.presetId}`)
        return outcome === 'cancelled' ? 'cancelled' : 'rejected'
      }

      // 防回环：本插件自己发起的转人工请求，交给浏览器/其他应答者。
      if (takePending(session, req.callId) || String(req.reason ?? '').startsWith(HUMAN_TAG)) {
        return next()
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
    `permission-matrix: loaded ${PRESETS.length} presets; takeover=${JSON.stringify(config.takeover)}; riskPolicies=${JSON.stringify(config.riskPolicies)}; llmJudge=${config.llmJudge}; robotWorkspaces=${config.robotWorkspaces.length}; approvalPassword=${passwordApproval.passwordSet() ? 'set' : 'unset'}`,
  )
}
