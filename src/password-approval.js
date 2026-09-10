/**
 * 「密码批准」通道 —— 与「放行 / 拒绝 / 转人工」并列的第四种审批方式。
 *
 * 任何风险档（低 / 中 / 高 / 极高）都可以把策略配成 `password`：该档的操作会被**挂起**，
 * 由本插件的密码弹窗（`shell.overlay`）/ 设置页 / 批准页要求输入批准密码，输对了当场放行，
 * 输错或超时则拒绝。`ask`（转人工）与它的区别是：转人工只是点一下「同意」，
 * 而密码批准要求知道口令——因此不会被"多点几次同意"绕过。
 *
 * 为什么要有它：v0.2 的「极高风险双重人工确认」要求「模型在窗口内原样重发同一条命令」
 * 才能完成第 2 次放行，而模型被拒后通常改路径重试（指纹随之改变），实测审计 1000+ 条中
 * `hard-confirm-2` 从未出现——等于那条路根本走不通。密码批准只取决于"是否知道口令"，
 * 与模型行为无关。
 *
 * 语义（fail-closed）：
 *   1. 被挂起的调用登记一条「待批准请求」（内存，重启即失效）；
 *   2. 用户输入批准密码 → 校验 scrypt 哈希 → 若调用仍在等则**当场放行**，
 *      否则签发**一次性令牌**（绑定该指纹，供模型重试时消费）；
 *   3. 未设置密码 → 一律拒绝（不存在"无密码放行"路径）。
 *
 * 密码只以 scrypt 哈希（salt + 参数）落在 settings 文档里，明文既不持久化也不回传浏览器。
 *
 * @module dsh-permission-matrix/password-approval
 */

import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto'

/** scrypt 参数：N=2^14 对本地口令足够，且设置页交互无感。 */
const SCRYPT = Object.freeze({ N: 16384, r: 8, p: 1, keylen: 32 })

/** 哈希串前缀（便于将来换算法）。 */
const HASH_PREFIX = 'scrypt'

/** 令牌默认有效期（毫秒）：5 分钟。 */
export const DEFAULT_TTL_MS = 300000

/** 最少密码长度：太低等于没有密码，太高逼用户写便签。 */
export const MIN_PASSWORD_LENGTH = 6

/** 待批准请求的保留上限（防止异常刷屏）。 */
const MAX_PENDING = 32

/** 待批准请求的保留时长（超过即视为过期不再展示）。 */
const PENDING_TTL_MS = 1800000

/**
 * 计算口令哈希：`scrypt$N$r$p$salt$key`（全部 base64）。
 * @param {string} plain - 明文口令。
 * @returns {string} 可持久化的哈希串。
 */
export function hashPassword(plain) {
  const salt = randomBytes(16)
  const key = scryptSync(String(plain), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p })
  return [HASH_PREFIX, SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), key.toString('base64')].join('$')
}

/**
 * 校验口令（恒定时间比较；任何结构异常一律判否，不抛错）。
 * @param {string} plain - 明文口令。
 * @param {string} stored - 存储的哈希串。
 * @returns {boolean} 是否匹配。
 */
export function verifyPassword(plain, stored) {
  const parts = String(stored ?? '').split('$')
  if (parts.length !== 6 || parts[0] !== HASH_PREFIX) return false
  const N = Number(parts[1])
  const r = Number(parts[2])
  const p = Number(parts[3])
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p) || N <= 0 || r <= 0 || p <= 0) return false
  let salt
  let expected
  try {
    salt = Buffer.from(parts[4], 'base64')
    expected = Buffer.from(parts[5], 'base64')
  } catch {
    return false
  }
  if (salt.length === 0 || expected.length === 0) return false
  let actual
  try {
    actual = scryptSync(String(plain), salt, expected.length, { N, r, p })
  } catch {
    return false
  }
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}

/**
 * 构造批准密码管理器（内存状态 + 配置读口）。
 * @param {() => object} getConfig - 读取当前配置（settings 可热覆盖）。
 * @param {{warn?: (message: string) => void}} [logger] - 可选日志。
 * @param {() => number} [clock] - 时钟（测试注入）。
 * @returns {object} 管理器 API。
 */
export function makePasswordApproval(getConfig, logger, clock) {
  const now = typeof clock === 'function' ? clock : () => Date.now()

  /** 待批准请求：id → record。 */
  const pending = new Map()
  /** 已签发令牌：id → grant。 */
  const grants = new Map()
  /** 正挂在审批瀑布里等密码的调用：requestId → { promise, finish }。 */
  const waiters = new Map()

  const ttlMs = () => {
    const config = getConfig() ?? {}
    // `hardApprovalTtlMs` 是 v0.3.0 的旧键（当时只服务极高风险），保留兼容读取。
    const value = Number(config.approvalPasswordTtlMs ?? config.hardApprovalTtlMs)
    return Number.isFinite(value) && value > 0 ? value : DEFAULT_TTL_MS
  }
  const storedHash = () => {
    const config = getConfig() ?? {}
    // 新键优先；旧键（v0.3.0 的 hardApprovalPasswordHash）继续可读，改名不丢已设口令。
    return String(config.approvalPasswordHash ?? '') || String(config.hardApprovalPasswordHash ?? '')
  }
  const passwordSet = () => storedHash() !== ''

  const prune = () => {
    const t = now()
    for (const [id, grant] of grants) {
      if (grant.expiresAt <= t) grants.delete(id)
    }
    for (const [id, record] of pending) {
      if (t - record.at > PENDING_TTL_MS) pending.delete(id)
    }
    while (pending.size > MAX_PENDING) {
      const oldest = [...pending.values()].sort((a, b) => a.at - b.at)[0]
      if (oldest === undefined) break
      pending.delete(oldest.id)
    }
  }

  /**
   * 校验一个待写入的新密码，返回可持久化的哈希。
   * @param {{currentPassword?: string, newPassword?: string, confirmPassword?: string}} input - 输入。
   * @returns {{ok: true, hash: string} | {ok: false, error: string}} 结果。
   */
  const preparePassword = ({ currentPassword, newPassword, confirmPassword } = {}) => {
    if (passwordSet() && !verifyPassword(String(currentPassword ?? ''), storedHash())) {
      return { ok: false, error: '当前批准密码不正确' }
    }
    const next = String(newPassword ?? '')
    if (next.length < MIN_PASSWORD_LENGTH) return { ok: false, error: `批准密码至少 ${MIN_PASSWORD_LENGTH} 位` }
    if (next !== String(confirmPassword ?? next)) return { ok: false, error: '两次输入的新密码不一致' }
    return { ok: true, hash: hashPassword(next) }
  }

  /**
   * 校验口令（用于批准动作）。
   * @param {string} password - 明文口令。
   * @returns {{ok: true} | {ok: false, error: string}} 结果。
   */
  const checkPassword = (password) => {
    if (!passwordSet()) return { ok: false, error: '尚未设置「批准密码」，请先在设置页设置' }
    if (!verifyPassword(String(password ?? ''), storedHash())) return { ok: false, error: '批准密码不正确' }
    return { ok: true }
  }

  /**
   * 登记一条待批准的密码请求（同指纹未过期的请求复用同一条记录）。
   * @param {{sessionId?: string, fingerprint: string, toolName: string, target?: string, preset?: string, rule?: string, risk?: string}} input - 请求信息。
   * @returns {{id: string, reused: boolean}} 登记结果。
   */
  const registerRequest = (input) => {
    prune()
    const sessionId = String(input?.sessionId ?? '')
    const fingerprint = String(input?.fingerprint ?? '')
    for (const record of pending.values()) {
      if (record.fingerprint === fingerprint && record.sessionId === sessionId && record.approvedAt === null) {
        record.toolName = String(input?.toolName ?? record.toolName)
        record.target = String(input?.target ?? record.target)
        if (input?.risk !== undefined) record.risk = String(input.risk)
        return { id: record.id, reused: true }
      }
    }
    const id = `hr-${randomUUID().slice(0, 8)}`
    pending.set(id, {
      id,
      at: now(),
      sessionId,
      fingerprint,
      toolName: String(input?.toolName ?? ''),
      target: String(input?.target ?? '').slice(0, 300),
      preset: String(input?.preset ?? ''),
      rule: String(input?.rule ?? ''),
      risk: String(input?.risk ?? ''),
      approvedAt: null,
      approvedGrantId: null,
    })
    return { id, reused: false }
  }

  /**
   * 结算某个请求上的等待者。
   * @param {string} requestId - 请求 id。
   * @param {'allowed' | 'declined' | 'timeout' | 'cancelled'} outcome - 结论。
   * @returns {boolean} 是否有等待者被结算。
   */
  const settleWaiter = (requestId, outcome) => {
    const waiter = waiters.get(String(requestId ?? ''))
    if (waiter === undefined) return false
    waiter.finish(outcome)
    return true
  }

  /**
   * 让审批瀑布挂起、等待密码批准（GUI 弹窗与批准页两条通道都通向这里）。
   *
   * 这是「直接弹窗填写」的关键：被拦的调用**不会失败**，而是挂在那儿等密码；
   * 用户输对密码后本次调用立即放行，不需要模型重试。超时/取消则回落为拒绝，
   * 同时该请求仍留在待批准列表里——用户之后批准会签一张令牌，供模型重试使用。
   * @param {{requestId: string, timeoutMs?: number, signal?: object}} input - 输入。
   * @returns {Promise<'allowed' | 'declined' | 'timeout' | 'cancelled'>} 结论。
   */
  const waitForDecision = ({ requestId, timeoutMs, signal } = {}) => {
    const id = String(requestId ?? '')
    const existing = waiters.get(id)
    if (existing !== undefined) return existing.promise
    if (signal?.aborted === true) return Promise.resolve('cancelled')

    let resolveOutcome
    const promise = new Promise((resolve) => {
      resolveOutcome = resolve
    })
    let settled = false
    let timer = null
    let onAbort = null
    const finish = (outcome) => {
      if (settled) return
      settled = true
      if (timer !== null) clearTimeout(timer)
      if (onAbort !== null) signal?.removeEventListener?.('abort', onAbort)
      waiters.delete(id)
      resolveOutcome(outcome)
    }
    onAbort = () => finish('cancelled')
    timer = setTimeout(() => finish('timeout'), Math.max(0, Number(timeoutMs) || ttlMs()))
    signal?.addEventListener?.('abort', onAbort, { once: true })
    waiters.set(id, { promise, finish })
    return promise
  }

  /**
   * 按密码批准某条待批准请求（令牌绑定该请求的指纹与会话）。
   * @param {{requestId: string, password: string}} input - 输入。
   * @returns {{ok: boolean, error?: string, grant?: object}} 结果。
   */
  const approveRequest = ({ requestId, password } = {}) => {
    prune()
    const verdict = checkPassword(password)
    if (!verdict.ok) return { ok: false, error: verdict.error }
    const record = pending.get(String(requestId ?? ''))
    if (record === undefined) return { ok: false, error: '找不到该待批准请求（可能已过期或已被处理）' }
    if (record.approvedAt !== null) return { ok: false, error: '该请求已被批准' }
    // 该调用仍挂在审批瀑布里等密码 → 直接放行本次调用（无需模型重试）
    if (waiters.has(record.id)) {
      record.approvedAt = now()
      settleWaiter(record.id, 'allowed')
      logger?.warn?.(`password-approval: delivered ${record.toolName} (${record.id}) to the waiting call`)
      return { ok: true, delivered: 'call' }
    }
    const grant = {
      id: `hg-${randomUUID().slice(0, 8)}`,
      at: now(),
      expiresAt: now() + ttlMs(),
      sessionId: record.sessionId === '' ? null : record.sessionId,
      fingerprint: record.fingerprint,
      toolName: record.toolName,
      requestId: record.id,
    }
    grants.set(grant.id, grant)
    record.approvedAt = now()
    record.approvedGrantId = grant.id
    logger?.warn?.(`password-approval: granted ${record.toolName} (${record.id}) → ${grant.id}`)
    return { ok: true, delivered: 'grant', grant: describeGrant(grant) }
  }

  /**
   * 按密码签发一张「下一次需密码操作」通配令牌（不绑定具体请求）。
   * @param {{password: string, sessionId?: string}} input - 输入。
   * @returns {{ok: boolean, error?: string, grant?: object}} 结果。
   */
  const authorizeNext = ({ password, sessionId } = {}) => {
    prune()
    const verdict = checkPassword(password)
    if (!verdict.ok) return { ok: false, error: verdict.error }
    const grant = {
      id: `hg-${randomUUID().slice(0, 8)}`,
      at: now(),
      expiresAt: now() + ttlMs(),
      sessionId: sessionId === undefined || sessionId === '' ? null : String(sessionId),
      fingerprint: null,
      toolName: '',
      requestId: null,
    }
    grants.set(grant.id, grant)
    logger?.warn?.(`password-approval: authorized next password-gated operation → ${grant.id}`)
    return { ok: true, grant: describeGrant(grant) }
  }

  /**
   * 消费一张令牌（命中即失效）。绑定指纹的令牌优先于通配令牌。
   * @param {{sessionId?: string, fingerprint: string}} input - 调用上下文。
   * @returns {object | null} 命中的令牌描述，或 null。
   */
  const consume = ({ sessionId, fingerprint } = {}) => {
    prune()
    const sid = sessionId === undefined || sessionId === null || sessionId === '' ? null : String(sessionId)
    const fp = String(fingerprint ?? '')
    const candidates = [...grants.values()].filter((grant) => {
      const sessionOk = grant.sessionId === null || grant.sessionId === sid
      if (!sessionOk) return false
      if (grant.fingerprint === null) return true
      return grant.fingerprint === fp
    })
    if (candidates.length === 0) return null
    candidates.sort((a, b) => {
      const exactA = a.fingerprint === null ? 1 : 0
      const exactB = b.fingerprint === null ? 1 : 0
      return exactA - exactB || a.at - b.at
    })
    const hit = candidates[0]
    grants.delete(hit.id)
    if (hit.requestId !== null) {
      const record = pending.get(hit.requestId)
      if (record !== undefined) {
        record.consumedAt = now()
        pending.delete(hit.requestId)
      }
    }
    return describeGrant(hit)
  }

  /** 令牌的可公开描述（不含密码）。 */
  function describeGrant(grant) {
    return {
      id: grant.id,
      at: new Date(grant.at).toISOString(),
      expiresInMs: Math.max(0, grant.expiresAt - now()),
      sessionId: grant.sessionId,
      scope: grant.fingerprint === null ? 'next-hard-operation' : 'pinned-request',
      toolName: grant.toolName,
      requestId: grant.requestId,
    }
  }

  /**
   * 供设置页展示的只读快照（不含哈希、不含密码）。
   * @returns {object} 快照。
   */
  const snapshot = () => {
    prune()
    const t = now()
    return {
      passwordSet: passwordSet(),
      minPasswordLength: MIN_PASSWORD_LENGTH,
      ttlMs: ttlMs(),
      pending: [...pending.values()]
        .filter((record) => record.approvedAt === null)
        .sort((a, b) => b.at - a.at)
        .map((record) => ({
          id: record.id,
          at: new Date(record.at).toISOString(),
          toolName: record.toolName,
          target: record.target,
          preset: record.preset,
          rule: record.rule,
          risk: record.risk ?? '',
          sessionId: record.sessionId,
          waiting: waiters.has(record.id),
        })),
      grants: [...grants.values()]
        .filter((grant) => grant.expiresAt > t)
        .sort((a, b) => b.at - a.at)
        .map(describeGrant),
      approved: [...pending.values()]
        .filter((record) => record.approvedAt !== null && record.consumedAt === undefined)
        .sort((a, b) => b.approvedAt - a.at)
        .slice(0, 10)
        .map((record) => ({
          id: record.id,
          at: new Date(record.at).toISOString(),
          approvedAt: new Date(record.approvedAt).toISOString(),
          toolName: record.toolName,
          target: record.target,
        })),
    }
  }

  /**
   * 丢弃一条待批准请求（用户误触拦截时清理；若该调用仍挂着等待，则按拒绝结算）。
   * @param {string} requestId - 请求 id。
   * @returns {boolean} 是否处理了该请求。
   */
  const dismissRequest = (requestId) => {
    const id = String(requestId ?? '')
    const settled = settleWaiter(id, 'declined')
    const existed = pending.delete(id)
    return settled || existed
  }

  return {
    passwordSet,
    preparePassword,
    checkPassword,
    registerRequest,
    approveRequest,
    authorizeNext,
    consume,
    snapshot,
    dismissRequest,
    waitForDecision,
    ttlMs,
  }
}
