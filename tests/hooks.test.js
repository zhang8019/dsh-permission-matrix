/**
 * 钩子行为集成测试（用 fake ctx 模拟 Cordis 上下文）。
 * 运行：node --test tests/hooks.test.js
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { apply, Config } from '../src/index.js'

const WORKSPACE = 'C:\\work\\proj'

/** 构造一个最小 fake ctx：记录监听器、提供 permissionPresets 与 logger。 */
function makeFakeCtx(presetOfSession = {}) {
  const handlers = new Map()
  const logs = []
  const switches = []
  const ctx = {
    logger: {
      info: (message) => logs.push({ level: 'info', message }),
      warn: (message) => logs.push({ level: 'warn', message }),
    },
    on: (name, handler) => {
      handlers.set(name, handler)
    },
    // 模拟"可选服务不可用"：不执行回调，插件应退回 composition 层配置
    inject: () => undefined,
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
      return undefined
    },
  }
  return { ctx, handlers, logs, switches }
}

/** 构造完整配置（用 Schema 默认值 + 覆盖）。 */
function makeConfig(overrides = {}) {
  return {
    enabled: true,
    takeover: { 'fa-auto': 'auto-allow', 'ww-classify': 'classify', 'fa-classify': 'classify' },
    riskPolicies: { low: 'allow', medium: 'deny', high: 'deny' },
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
