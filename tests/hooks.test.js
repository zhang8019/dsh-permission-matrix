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
    riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'deny' },
    hardConfirmWindowMs: 120000,
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

// ── 下一版本修复：极高风险双重人工确认 / 高风险档 ask ───────────────────────

test('Config：riskPolicies.hard 默认 deny，可配置 ask', () => {
  const parsed = Config({})
  assert.equal(parsed.riskPolicies.hard, 'deny')
  assert.equal(parsed.hardConfirmWindowMs, 120000)
})

test('极高风险双重确认（classify 档 hard=ask）：第1次同意→拒绝，相同调用第2次放行', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'ww-classify' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' }, llmJudge: false }))
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  const first = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(first.kind, 'ask')
  assert.match(first.reason, /双重人工确认/, 'reason 必须说明双重确认流程')
  assert.match(first.reason, /^\[pm\]/, 'reason 必须带防回环标记')

  const approved = await approval({ agent: { session }, toolName: 'pwsh', callId: 'c1', reason: first.reason }, () => Promise.resolve('allowed-once'))
  assert.equal(approved, 'rejected', '第1次人工同意只登记，本次调用仍被拒绝')

  const second = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c2' }, allowNext)
  assert.equal(second.kind, 'allow', '窗口内相同指纹的第2次调用直接放行')
})

test('极高风险双重确认：第1次被用户拒绝则不记录，后续仍走第1次', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'ww-classify' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' }, llmJudge: false }))
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  const first = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  await approval({ agent: { session }, toolName: 'pwsh', callId: 'c1', reason: first.reason }, () => Promise.resolve('rejected'))

  const retry = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c2' }, allowNext)
  assert.equal(retry.kind, 'ask', '用户拒绝后不记录确认，需重新走第1次')
})

test('极高风险双重确认：不同命令不共享确认，窗口过期需重新确认', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'ww-classify' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' }, hardConfirmWindowMs: 0, llmJudge: false }))
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  const first = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(first.kind, 'ask')
  await approval({ agent: { session }, toolName: 'pwsh', callId: 'c1', reason: first.reason }, () => Promise.resolve('allowed-once'))

  const different = await pre({ name: 'pwsh', arguments: { command: 'Remove-Item -Recurse -Force C:\\' }, agent: { session }, callId: 'c2' }, allowNext)
  assert.equal(different.kind, 'ask', '不同命令（不同 HARD 盘根删除）指纹不命中，需重新第1次')

  const again = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c3' }, allowNext)
  assert.equal(again.kind, 'ask', '窗口过期（0ms）后需重新双重确认')
})

test('自动同意档 + hard=ask：极高风险也走双重确认', async () => {
  const { ctx, handlers } = makeFakeCtx({ s1: 'fa-auto' })
  apply(ctx, makeConfig({ riskPolicies: { low: 'allow', medium: 'deny', high: 'deny', hard: 'ask' } }))
  const pre = handlers.get('tools/pre-execute')
  const approval = handlers.get('approval/request')
  const session = sessionOf('s1')

  const first = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c1' }, allowNext)
  assert.equal(first.kind, 'ask', 'hard=ask 时自动同意档不再直接拒绝')

  const approved = await approval({ agent: { session }, toolName: 'pwsh', callId: 'c1', reason: first.reason }, () => Promise.resolve('allowed-once'))
  assert.equal(approved, 'rejected')

  const second = await pre({ name: 'pwsh', arguments: { command: 'rm -rf /' }, agent: { session }, callId: 'c2' }, allowNext)
  assert.equal(second.kind, 'allow')
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
