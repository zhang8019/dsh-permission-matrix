/**
 * 钩子行为集成测试（用 fake ctx 模拟 Cordis 上下文）。
 * 运行：node --test tests/hooks.test.js
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { apply, Config } from '../src/index.js'

const WORKSPACE = 'C:\\work\\proj'

/** 构造一个最小 fake ctx：记录监听器、提供 permissionPresets 与 logger。
 * @param {object} presetOfSession - 会话 → 预设映射。
 * @param {{web?: boolean, config?: object}} [options] - `web: true` 时额外提供 webServer
 *   与 settings 服务，用于端到端驱动「极高风险批准密码」路由。
 */
function makeFakeCtx(presetOfSession = {}, options = {}) {
  const handlers = new Map()
  const logs = []
  const switches = []
  const routes = new Map()
  const mutations = []
  const target = options.config ?? null
  const ctx = {
    logger: {
      info: (message) => logs.push({ level: 'info', message }),
      warn: (message) => logs.push({ level: 'warn', message }),
    },
    on: (name, handler) => {
      handlers.set(name, handler)
    },
    // 无 webServer 时模拟"服务不可用"：不执行回调，插件应退回 composition 层配置
    inject: (services, callback) => {
      const list = Array.isArray(services) ? services : [services]
      if (options.web === true && list.includes('webServer') && typeof callback === 'function') callback(ctx)
      return undefined
    },
    effect: (factory) => {
      const dispose = factory()
      return typeof dispose === 'function' ? dispose : () => undefined
    },
    get: (service) => {
      if (service === 'permissionPresets') {
        return {
          current: (session) => presetOfSession[session?.id] ?? 'ww-human',
          set: (session, name) => {
            switches.push({ sessionId: session?.id, name })
            presetOfSession[session.id] = name
          },
        }
      }
      if (service === 'sessionProjections') return { stateOf: () => undefined }
      if (service === 'webServer' && options.web === true) {
        return {
          register: (spec) => {
            routes.set(spec.path, spec.handler)
            return () => routes.delete(spec.path)
          },
        }
      }
      if (service === 'settings' && options.web === true) {
        return {
          mutate: async (namespace, ops) => {
            mutations.push({ namespace, ops })
            for (const op of ops) {
              if (op?.op === 'set' && Array.isArray(op.path) && op.path.length === 1 && target !== null) target[op.path[0]] = op.value
            }
          },
        }
      }
      return undefined
    },
  }
  return { ctx, handlers, logs, switches, routes, mutations }
}

/**
 * 以内存 req/res 调用插件注册的 web 路由。
 * @param {Map<string, Function>} routes - 路由表。
 * @param {string} path - 精确路径。
 * @param {{method?: string, body?: object}} [init] - 请求参数。
 * @returns {Promise<{status: number, body: object}>} 响应。
 */
async function callRoute(routes, path, init = {}) {
  const handler = routes.get(path)
  assert.ok(typeof handler === 'function', `route not registered: ${path}`)
  const chunks = init.body === undefined ? [] : [Buffer.from(JSON.stringify(init.body))]
  const req = {
    method: init.method ?? 'GET',
    url: path,
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) yield chunk
    },
  }
  const res = {
    status: 0,
    body: null,
    writeHead(status) {
      this.status = status
    },
    end(text) {
      this.body = text === undefined || text === '' ? null : JSON.parse(text)
    },
  }
  await handler(req, res)
  return { status: res.status, body: res.body }
}

/** 构造完整配置（用 Schema 默认值 + 覆盖）。 */
function makeConfig(overrides = {}) {
  return {
    enabled: true,
    takeover: { 'fa-auto': 'auto-allow', 'ww-classify': 'classify', 'fa-classify': 'classify' },
    riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'deny' },
    approvalPasswordHash: '',
    approvalPasswordTtlMs: 300000,
    llmJudge: false,
    judgeProvider: '',
    judgeModel: '',
    judgeStages: 'both',
    autoAllowHardGuard: true,
    robotDefaultPreset: 'fa-auto',
    robotWorkspaces: [],
    gitSnapshot: false,
    gitSnapshotIntervalMs: 30000,
    auditLog: false,
    auditFile: '',
    ...overrides,
  }
}

const sessionOf = (id) => ({ id, header: { cwd: WORKSPACE } })
const allowNext = () => Promise.resolve({ kind: 'allow' })

test('Config：默认值可解析且 takeover 默认表正确', () => {
  const parsed = Config({})
  assert.equal(parsed.enabled, true)
  assert.equal(parsed.riskPolicies.medium, 'deny')
  assert.equal(parsed.riskPolicies.low, 'allow')
  assert.equal(parsed.takeover['fa-auto'], 'auto-allow')
})

test('人工审批预设：插件不干预（pre-execute 与 approval 均 next）', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'ww-human' })
  apply(ctx, makeConfig())

  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  const preResult = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(preResult.kind, 'allow', '人工审批档不应拦截')

  const approvalResult = await approval({ agent: { session }, toolName: 'pwsh', callId: 'c1' }, () => Promise.resolve('unavailable'))
  assert.equal(approvalResult, 'unavailable', '人工审批档应交给下游应答者')
})

test('自动同意预设：危险命令被硬拒绝，安全命令放行，审批自动同意', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'fa-auto' })
  apply(ctx, makeConfig())
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  const denied = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(denied.kind, 'deny', '硬拒绝必须在 pre-execute 拦截')

  const passed = await pre({ name: 'pwsh', arguments: { command: 'git status' }, agent: { session }, callId: 'c2' }, allowNext)
  assert.equal(passed.kind, 'allow')

  const granted = await approval({ agent: { session }, toolName: 'pwsh', callId: 'c3', reason: 'escalate sandbox' }, () => Promise.resolve('unavailable'))
  assert.equal(granted, 'allowed-once', '自动同意档应自动批准')

  const guard = await approval({ agent: { session }, toolName: 'pwsh', callId: 'c4', reason: 'rm -rf /' }, () => Promise.resolve('unavailable'))
  assert.equal(guard, 'rejected', '自动同意档的硬拒绝保护应生效')
})

test('自动同意预设：硬拒绝保护可关闭', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'fa-auto' })
  apply(ctx, makeConfig({ autoAllowHardGuard: false }))
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')
  const granted = await approval({ agent: { session }, toolName: 'pwsh', callId: 'c1', reason: 'rm -rf /' }, () => Promise.resolve('unavailable'))
  assert.equal(granted, 'allowed-once')
})

test('自动风险审批预设 + 中档=拒绝：未命中 → deny；命中 allow 规则 → 放行', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'ww-classify' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny' }, llmJudge: false }))
  const pre = handlers.get('tools/pre-execute')
  const session = sessionOf('s1')

  const unknown = await pre({ name: 'write', arguments: { file_path: 'D:\\outside\\a.txt' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(unknown.kind, 'deny', '中档=拒绝时未命中应拒绝')

  const inWorkspace = await pre({ name: 'write', arguments: { file_path: 'C:\\work\\proj\\a.txt' }, agent: { session }, callId: 'c2' }, allowNext)
  assert.equal(inWorkspace.kind, 'allow')

  const dangerous = await pre({ name: 'pwsh', arguments: { command: 'format C:' }, agent: { session }, callId: 'c3' }, allowNext)
  assert.equal(dangerous.kind, 'deny')
})

test('自动风险审批预设 + 中档=转人工：未命中 → ask，且不自我裁决（防回环）', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'ww-classify' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'ask', high: 'deny' }, llmJudge: false }))
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  const asked = await pre({ name: 'write', arguments: { file_path: 'D:\\outside\\a.txt' }, agent: { session }, callId: 'c9' }, allowNext)
  assert.equal(asked.kind, 'ask')
  assert.match(asked.reason, /^\[pm\]/, 'reason 必须带防回环标记')

  // 同一 callId 的审批请求必须让位给人工应答者
  const delegated = await approval({ agent: { session }, toolName: 'write', callId: 'c9', reason: asked.reason }, () => Promise.resolve('unavailable'))
  assert.equal(delegated, 'unavailable', '插件不得裁决自己发起的转人工请求')
})

test('自动风险审批预设 + 中档=同意：未命中 → 放行', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'fa-classify' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'allow', high: 'deny' }, llmJudge: false }))
  const pre = handlers.get('tools/pre-execute')
  const session = sessionOf('s1')
  const result = await pre({ name: 'write', arguments: { file_path: 'D:\\outside\\a.txt' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(result.kind, 'allow')
})

test('机器人工作区：会话创建时切换为机器人默认预设', async () => {
  const presets = { s1: 'ww-human' }
  const { ctx, handlers, switches } = makeFakeCtx(presets)
  apply(ctx, makeConfig({ robotWorkspaces: ['C:\\bots\\qq'], robotDefaultPreset: 'fa-auto' }))

  const onCreated = handlers.get('session/created')
  onCreated({ id: 's1', header: { cwd: 'C:\\bots\\qq' } })
  assert.deepEqual(switches, [{ sessionId: 's1', name: 'fa-auto' }])

  onCreated({ id: 's2', header: { cwd: 'C:\\work\\proj' } })
  assert.equal(switches.length, 1, '非机器人工作区不应切换')
})

test('配置校验：未知预设 / 非法档位 / 未知机器人预设 → 响亮失败', () => {
  const { ctx } = makeFakeCtx()
  assert.throws(() => apply(ctx, makeConfig({ takeover: { nope: 'auto-allow' } })), /unknown preset/)
  assert.throws(() => apply(ctx, makeConfig({ takeover: { 'fa-auto': 'weird' } })), /tier must be/)
  assert.throws(() => apply(ctx, makeConfig({ robotDefaultPreset: 'nope' })), /not a known preset/)
})

test('总开关关闭：不注册任何钩子', () => {
  const { ctx, handlers } = makeFakeCtx()
  apply(ctx, makeConfig({ enabled: false }))
  assert.equal(handlers.size, 0)
})

// ── 极高风险「批准密码」通道（取代 v0.2 的双重人工确认） ───────────────────

test('Config：riskPolicies.hard 默认 deny；批准密码默认未设置', () => {
  const parsed = Config({})
  assert.equal(parsed.riskPolicies.hard, 'deny')
  assert.equal(parsed.approvalPasswordHash, '')
  assert.equal(parsed.approvalPasswordTtlMs, 300000)
})

test('极高风险（hard=ask）未设置批准密码：挂起为 ask，并提示先设置密码', async () => {
  const config = makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' }, llmJudge: false })
  const { ctx, handlers } = makeFakeCtx({ s1: 'ww-classify' }, { config })
  apply(ctx, config)
  const pre = handlers.get('tools/pre-execute')
  const session = sessionOf('s1')

  const result = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(result.kind, 'ask', '极高风险挂起等密码，而不是交给浏览器审批')
  assert.match(result.reason, /需批准密码/)
  assert.match(result.reason, /尚未设置/)
})

test('极高风险批准密码：弹窗输入密码 → 被挂起的调用立即放行（端到端）', async () => {
  const config = makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' }, llmJudge: false })
  const { ctx, handlers, routes, mutations } = makeFakeCtx({ s1: 'ww-classify' }, { web: true, config })
  apply(ctx, config)
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  // 设置批准密码：哈希写入 settings，明文既不落盘也不回传
  const setRes = await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'set-password', newPassword: 'probe-pass-123', confirmPassword: 'probe-pass-123' },
  })
  assert.equal(setRes.status, 200)
  assert.equal(setRes.body.passwordSet, true)
  assert.ok(
    mutations.some((entry) => entry.ops.some((op) => op.path[0] === 'approvalPasswordHash')),
    '哈希必须经 settings 写入',
  )
  assert.ok(!JSON.stringify(setRes.body).includes('probe-pass-123'), '响应里不得出现明文口令')

  // 1) 极高风险 → ask（登记待批准请求并挂起）
  const asked = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(asked.kind, 'ask')

  // 2) DSH 发起审批：插件挂起等密码，**不调 next()**（浏览器审批弹窗不参与）
  let downstreamCalled = false
  const pendingApproval = approval({ agent: { session }, toolName: 'pwsh', callId: 'c1', reason: asked.reason }, () => {
    downstreamCalled = true
    return Promise.resolve('unavailable')
  })

  // 3) 用户在弹窗里输入密码（经 /hard-approval 路由，与 GUI 弹窗同一条通道）
  const list = await callRoute(routes, '/dsh-permission-matrix/password-approval')
  assert.equal(list.body.pending.length, 1, '挂起后应出现一条待批准请求')
  assert.equal(list.body.pending[0].waiting, true, '该请求应标记为「等待中」')
  const approveRes = await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'approve', requestId: list.body.pending[0].id, password: 'probe-pass-123' },
  })
  assert.equal(approveRes.status, 200)
  assert.equal(approveRes.body.delivered, 'call', '应把放行直接交给挂起的那次调用')

  // 4) 被挂起的调用立刻拿到 allowed-once，且没惊动浏览器应答者
  assert.equal(await pendingApproval, 'allowed-once')
  assert.equal(downstreamCalled, false, '极高风险不得走人工审批应答者')
})

test('任意风险档都能选「密码批准」：以中风险为例，挂起 → 输密码 → 立即放行', async () => {
  const config = makeConfig({ riskPolicies: { low: 'allow', medium: 'password', high: 'deny', hard: 'deny' }, llmJudge: false })
  const { ctx, handlers, routes } = makeFakeCtx({ s1: 'ww-classify' }, { web: true, config })
  apply(ctx, config)
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'set-password', newPassword: 'probe-pass-123', confirmPassword: 'probe-pass-123' },
  })

  // 工作区外的 write：规则未命中 + 裁判关闭 → 落到中风险档
  const call = { name: 'write', arguments: { file_path: 'D:\\outside\\a.txt' }, agent: { session } }
  const asked = await pre({ ...call, callId: 'c1' }, allowNext)
  assert.equal(asked.kind, 'ask', '中风险档配 password 时应挂起等密码')
  assert.match(asked.reason, /中风险操作需批准密码/)

  const pendingApproval = approval({ agent: { session }, toolName: 'write', callId: 'c1', reason: asked.reason }, () => Promise.resolve('unavailable'))
  const list = await callRoute(routes, '/dsh-permission-matrix/password-approval')
  assert.equal(list.body.pending.length, 1)
  assert.equal(list.body.pending[0].risk, 'medium', '待批准请求应记录风险级别')

  const res = await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'approve', requestId: list.body.pending[0].id, password: 'probe-pass-123' },
  })
  assert.equal(res.body.delivered, 'call')
  assert.equal(await pendingApproval, 'allowed-once', '中风险档同样凭密码当场放行')
})

test('极高风险批准密码：口令错误不放行；令牌只绑定被批准的那个操作', async () => {
  const config = makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' }, llmJudge: false })
  const { ctx, handlers, routes } = makeFakeCtx({ s1: 'ww-classify' }, { web: true, config })
  apply(ctx, config)
  const pre = handlers.get('tools/pre-execute')
  const session = sessionOf('s1')

  await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'set-password', newPassword: 'right-pass-1', confirmPassword: 'right-pass-1' },
  })

  const asked = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(asked.kind, 'ask')
  const list = await callRoute(routes, '/dsh-permission-matrix/password-approval')
  const requestId = list.body.pending[0].id

  const wrong = await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'approve', requestId, password: 'wrong-pass' },
  })
  assert.equal(wrong.status, 400)
  assert.equal(wrong.body.ok, false)

  // 此刻没有等待者（调用已经结束）→ 批准签的是令牌，供模型重试使用
  const granted = await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'approve', requestId, password: 'right-pass-1' },
  })
  assert.equal(granted.body.ok, true)
  assert.equal(granted.body.delivered, 'grant')

  const other = await pre({ name: 'pwsh', arguments: { command: 'Remove-Item -Recurse -Force C:\\' }, agent: { session }, callId: 'c2' }, allowNext)
  assert.equal(other.kind, 'ask', '令牌绑定指纹，不覆盖别的极高风险操作')

  const same = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c3' }, allowNext)
  assert.equal(same.kind, 'allow', '被批准的那条操作才放行')
})

test('极高风险批准密码：超时未批准 → 拒绝；事后批准可生成令牌供重试放行', async () => {
  const config = makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' }, approvalPasswordTtlMs: 60, llmJudge: false })
  const { ctx, handlers, routes } = makeFakeCtx({ s1: 'ww-classify' }, { web: true, config })
  apply(ctx, config)
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')
  const call = { name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session } }

  await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'set-password', newPassword: 'right-pass-1', confirmPassword: 'right-pass-1' },
  })

  const asked = await pre({ ...call, callId: 'c1' }, allowNext)
  assert.equal(asked.kind, 'ask')
  const outcome = await approval({ agent: { session }, toolName: 'pwsh', callId: 'c1', reason: asked.reason }, () => Promise.resolve('unavailable'))
  assert.equal(outcome, 'rejected', '窗口内没等到密码 → 按拒绝处理')

  const list = await callRoute(routes, '/dsh-permission-matrix/password-approval')
  assert.equal(list.body.pending.length, 1, '超时后请求仍保留，用户可事后批准')
  const res = await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'approve', requestId: list.body.pending[0].id, password: 'right-pass-1' },
  })
  assert.equal(res.body.delivered, 'grant')
  assert.equal((await pre({ ...call, callId: 'c2' }, allowNext)).kind, 'allow', '事后批准 → 模型重试即放行')
})

test('极高风险批准密码：忽略（dismiss）→ 挂起的调用立即按拒绝处理', async () => {
  const config = makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' }, llmJudge: false })
  const { ctx, handlers, routes } = makeFakeCtx({ s1: 'ww-classify' }, { web: true, config })
  apply(ctx, config)
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'set-password', newPassword: 'right-pass-1', confirmPassword: 'right-pass-1' },
  })

  const asked = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(asked.kind, 'ask')
  const pendingApproval = approval({ agent: { session }, toolName: 'pwsh', callId: 'c1', reason: asked.reason }, () => Promise.resolve('unavailable'))
  const list = await callRoute(routes, '/dsh-permission-matrix/password-approval')
  await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'dismiss', requestId: list.body.pending[0].id },
  })
  assert.equal(await pendingApproval, 'rejected', '忽略应让挂起的调用立刻失败')
})

test('极高风险批准密码：授权「下一次」为通配令牌，放行一次后失效', async () => {
  const config = makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' }, llmJudge: false })
  const { ctx, handlers, routes } = makeFakeCtx({ s1: 'ww-classify' }, { web: true, config })
  apply(ctx, config)
  const pre = handlers.get('tools/pre-execute')
  const session = sessionOf('s1')

  await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'set-password', newPassword: 'right-pass-1', confirmPassword: 'right-pass-1' },
  })
  const auth = await callRoute(routes, '/dsh-permission-matrix/password-approval', {
    method: 'POST',
    body: { action: 'authorize-next', password: 'right-pass-1' },
  })
  assert.equal(auth.body.ok, true)

  const first = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(first.kind, 'allow')
  const second = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c2' }, allowNext)
  assert.equal(second.kind, 'ask', '通配令牌同样只用一次，第二次回到等密码')
})

test('自动同意档 + hard=ask：极高风险不被自动放行，走批准密码闸门', async () => {
  const config = makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' } })
  const { ctx, handlers } = makeFakeCtx({ s1: 'fa-auto' }, { config })
  apply(ctx, config)
  const pre = handlers.get('tools/pre-execute')
  const session = sessionOf('s1')

  const blocked = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(blocked.kind, 'ask', '自动同意档也不得自动放行极高风险')
  assert.match(blocked.reason, /需批准密码/)
})

test('自动同意档 + hard=deny：极高风险保持直接拒绝（现状不变）', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'fa-auto' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'deny' } }))
  const pre = handlers.get('tools/pre-execute')
  const session = sessionOf('s1')
  const denied = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(denied.kind, 'deny')
})

test('高风险档=ask（classify）：非盘根递归删除转人工，一次同意放行', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'ww-classify' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'ask', hard: 'deny' }, llmJudge: false }))
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  const first = await pre({ name: 'pwsh', arguments: { command: 'Remove-Item -Recurse -Force C:\\Users\\Public\\testfolder' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(first.kind, 'ask')
  assert.match(first.reason, /需人工确认/)

  const approved = await approval({ agent: { session }, toolName: 'pwsh', callId: 'c1', reason: first.reason }, () => Promise.resolve('allowed-once'))
  assert.equal(approved, 'allowed-once', '高风险一次人工同意即可放行（不要求两次）')
})

test('高风险档=deny（classify）：非盘根递归删除被拒绝', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'ww-classify' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'deny' }, llmJudge: false }))
  const pre = handlers.get('tools/pre-execute')
  const session = sessionOf('s1')
  const result = await pre({ name: 'pwsh', arguments: { command: 'rm -rf ~/Downloads/testfolder' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(result.kind, 'deny')
})

test('工作区内递归删除豁免：不弹窗直接放行（即使 high=ask）', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'ww-classify' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'ask', hard: 'deny' }, llmJudge: false }))
  const pre = handlers.get('tools/pre-execute')
  const session = sessionOf('s1')
  const result = await pre({ name: 'pwsh', arguments: { command: 'Remove-Item -Recurse -Force C:\\work\\proj\\dist' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(result.kind, 'allow')
})
