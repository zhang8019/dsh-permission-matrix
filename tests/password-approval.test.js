/**
 * 「密码批准」模块单测：哈希、令牌一次性、指纹绑定、TTL、挂起等待。
 * 运行：node --test tests/password-approval.test.js
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { hashPassword, makePasswordApproval, verifyPassword } from '../src/password-approval.js'

/** 构造「配置 + 管理器」（配置对象可变，模拟 settings 热覆盖）。 */
function makeManager(overrides = {}, clock) {
  const config = { approvalPasswordHash: '', approvalPasswordTtlMs: 300000, ...overrides }
  return { config, manager: makePasswordApproval(() => config, undefined, clock) }
}

/** 设置一个可用口令，返回明文。 */
function armPassword(manager, config, plain = 'secret-pass') {
  const prepared = manager.preparePassword({ newPassword: plain, confirmPassword: plain })
  assert.equal(prepared.ok, true)
  config.approvalPasswordHash = prepared.hash
  return plain
}

test('hashPassword / verifyPassword：正确口令通过，错误口令与畸形哈希一律拒绝', () => {
  const hash = hashPassword('correct horse')
  assert.match(hash, /^scrypt\$16384\$8\$1\$/)
  assert.equal(verifyPassword('correct horse', hash), true)
  assert.equal(verifyPassword('Correct horse', hash), false)
  assert.equal(verifyPassword('', hash), false)
  assert.equal(verifyPassword('correct horse', ''), false)
  assert.equal(verifyPassword('correct horse', 'plain-text'), false)
  assert.equal(verifyPassword('correct horse', 'scrypt$16384$8$1$@@@$@@@'), false)
  assert.equal(verifyPassword('correct horse', 'scrypt$0$8$1$YWJj$YWJj'), false)
  assert.notEqual(hashPassword('correct horse'), hash, '同一口令两次哈希必须不同（盐随机）')
})

test('preparePassword：长度不足 / 两次不一致 / 当前口令错误都被拒', () => {
  const { config, manager } = makeManager()
  assert.equal(manager.preparePassword({ newPassword: 'short', confirmPassword: 'short' }).ok, false)
  assert.equal(manager.preparePassword({ newPassword: 'long-enough', confirmPassword: 'mismatch' }).ok, false)
  assert.equal(manager.passwordSet(), false)

  armPassword(manager, config, 'long-enough')
  assert.equal(manager.passwordSet(), true)
  assert.equal(
    manager.preparePassword({ currentPassword: 'nope', newPassword: 'another-one', confirmPassword: 'another-one' }).ok,
    false,
    '修改密码必须提供正确的当前口令',
  )
  assert.equal(
    manager.preparePassword({ currentPassword: 'long-enough', newPassword: 'another-one', confirmPassword: 'another-one' }).ok,
    true,
  )
})

test('未设置密码：所有批准动作一律失败（fail-closed）', () => {
  const { manager } = makeManager()
  assert.equal(manager.passwordSet(), false)
  assert.equal(manager.checkPassword('anything').ok, false)
  assert.equal(manager.authorizeNext({ password: 'anything' }).ok, false)
  const { id } = manager.registerRequest({ sessionId: 's1', fingerprint: 'f', toolName: 'pwsh' })
  assert.equal(manager.approveRequest({ requestId: id, password: 'anything' }).ok, false)
  assert.equal(manager.consume({ sessionId: 's1', fingerprint: 'f' }), null)
})

test('registerRequest：同会话同指纹复用同一条待批准请求', () => {
  const { manager } = makeManager()
  const first = manager.registerRequest({ sessionId: 's1', fingerprint: 'f', toolName: 'pwsh', target: 'x' })
  const second = manager.registerRequest({ sessionId: 's1', fingerprint: 'f', toolName: 'pwsh', target: 'y' })
  assert.equal(first.id, second.id)
  assert.equal(second.reused, true)
  assert.equal(manager.snapshot().pending.length, 1)
  assert.equal(manager.snapshot().pending[0].target, 'y')

  const other = manager.registerRequest({ sessionId: 's2', fingerprint: 'f', toolName: 'pwsh' })
  assert.notEqual(other.id, first.id, '不同会话不共享待批准请求')
})

test('批准 → 消费：令牌一次性、绑定指纹与会话', () => {
  const { config, manager } = makeManager()
  const plain = armPassword(manager, config)

  const { id } = manager.registerRequest({ sessionId: 's1', fingerprint: 'pwsh::rm -rf /', toolName: 'pwsh' })
  assert.equal(manager.snapshot().pending.length, 1)
  assert.equal(manager.approveRequest({ requestId: id, password: 'wrong-pass' }).ok, false, '口令错误不得签发令牌')
  assert.equal(manager.approveRequest({ requestId: 'hr-nope', password: plain }).ok, false, '未知请求不得签发令牌')

  const approved = manager.approveRequest({ requestId: id, password: plain })
  assert.equal(approved.ok, true)
  assert.equal(approved.grant.scope, 'pinned-request')
  assert.equal(manager.snapshot().pending.length, 0, '批准后该请求离开待批准列表')

  const consumed = manager.consume({ sessionId: 's1', fingerprint: 'pwsh::rm -rf /' })
  assert.equal(consumed?.id, approved.grant.id)
  assert.equal(manager.consume({ sessionId: 's1', fingerprint: 'pwsh::rm -rf /' }), null, '令牌用后即焚')

  const second = manager.registerRequest({ sessionId: 's1', fingerprint: 'pwsh::format c:', toolName: 'pwsh' })
  manager.approveRequest({ requestId: second.id, password: plain })
  assert.equal(manager.consume({ sessionId: 's1', fingerprint: 'pwsh::rm -rf /' }), null, '令牌不覆盖别的极高风险操作')
  assert.notEqual(manager.consume({ sessionId: 's1', fingerprint: 'pwsh::format c:' }), null)

  const third = manager.registerRequest({ sessionId: 's2', fingerprint: 'pwsh::git reset --hard', toolName: 'pwsh' })
  manager.approveRequest({ requestId: third.id, password: plain })
  assert.equal(manager.consume({ sessionId: 's3', fingerprint: 'pwsh::git reset --hard' }), null, '别的会话不能消费')
  assert.notEqual(manager.consume({ sessionId: 's2', fingerprint: 'pwsh::git reset --hard' }), null)
})

test('authorizeNext：通配令牌放行任意极高风险操作一次', () => {
  const { config, manager } = makeManager()
  const plain = armPassword(manager, config)

  const auth = manager.authorizeNext({ password: plain })
  assert.equal(auth.ok, true)
  assert.equal(auth.grant.scope, 'next-hard-operation')
  assert.notEqual(manager.consume({ sessionId: 'any-session', fingerprint: 'write::c:\\windows\\x' }), null)
  assert.equal(manager.consume({ sessionId: 'any-session', fingerprint: 'write::c:\\windows\\x' }), null, '通配令牌同样只用一次')
})

test('TTL：过期令牌不可消费（注入时钟）', () => {
  let now = 1_000_000
  const { config, manager } = makeManager({ approvalPasswordTtlMs: 60000 }, () => now)
  const plain = armPassword(manager, config)

  const { id } = manager.registerRequest({ sessionId: 's1', fingerprint: 'f', toolName: 'pwsh' })
  manager.approveRequest({ requestId: id, password: plain })

  now += 59999
  assert.notEqual(manager.consume({ sessionId: 's1', fingerprint: 'f' }), null, 'TTL 内可用')

  const { id: id2 } = manager.registerRequest({ sessionId: 's1', fingerprint: 'g', toolName: 'pwsh' })
  manager.approveRequest({ requestId: id2, password: plain })
  now += 60001
  assert.equal(manager.consume({ sessionId: 's1', fingerprint: 'g' }), null, '过期令牌不得消费')
})

test('snapshot：只暴露状态，不含口令哈希', () => {
  const { config, manager } = makeManager()
  armPassword(manager, config)
  const snap = manager.snapshot()
  assert.equal(snap.passwordSet, true)
  assert.equal(snap.ttlMs, 300000)
  assert.equal(JSON.stringify(snap).includes(config.approvalPasswordHash), false, '快照不得包含哈希')
  assert.equal(JSON.stringify(snap).includes('secret-pass'), false, '快照不得包含明文')
})

// ── 在审批瀑布里挂起等密码（弹窗填写的关键路径） ───────────────────────────

test('waitForDecision：密码批准 → allowed，并标记 waiting 状态', async () => {
  const { config, manager } = makeManager()
  const plain = armPassword(manager, config)
  const { id } = manager.registerRequest({ sessionId: 's1', fingerprint: 'f', toolName: 'pwsh' })

  const waiting = manager.waitForDecision({ requestId: id, timeoutMs: 1000 })
  assert.equal(manager.snapshot().pending[0].waiting, true, '挂起中应标记 waiting')

  const approved = manager.approveRequest({ requestId: id, password: plain })
  assert.equal(approved.ok, true)
  assert.equal(approved.delivered, 'call', '有等待者时应直接交付给该调用')
  assert.equal(await waiting, 'allowed')
  assert.equal(manager.snapshot().pending.length, 0, '放行后请求离开列表')
  assert.equal(manager.snapshot().grants.length, 0, '直接交付不签令牌')
})

test('waitForDecision：超时 → timeout；无等待者时批准改为签令牌', async () => {
  const { config, manager } = makeManager({ approvalPasswordTtlMs: 30 })
  const plain = armPassword(manager, config)
  const { id } = manager.registerRequest({ sessionId: 's1', fingerprint: 'f', toolName: 'pwsh' })

  const waiting = manager.waitForDecision({ requestId: id, timeoutMs: 30 })
  assert.equal(await waiting, 'timeout', '超时按 timeout 结算')
  assert.equal(manager.snapshot().pending[0].waiting, false)

  const approved = manager.approveRequest({ requestId: id, password: plain })
  assert.equal(approved.delivered, 'grant', '事后批准退化为令牌')
  assert.equal(manager.snapshot().grants.length, 1)
})

test('waitForDecision：dismiss → declined；signal 中止 → cancelled', async () => {
  const { config, manager } = makeManager()
  armPassword(manager, config)

  const first = manager.registerRequest({ sessionId: 's1', fingerprint: 'f', toolName: 'pwsh' })
  const waitingFirst = manager.waitForDecision({ requestId: first.id, timeoutMs: 1000 })
  manager.dismissRequest(first.id)
  assert.equal(await waitingFirst, 'declined', '忽略应结算为 declined')

  const second = manager.registerRequest({ sessionId: 's1', fingerprint: 'g', toolName: 'pwsh' })
  const controller = new AbortController()
  const waitingSecond = manager.waitForDecision({ requestId: second.id, timeoutMs: 1000, signal: controller.signal })
  controller.abort()
  assert.equal(await waitingSecond, 'cancelled', '调用被取消应结算为 cancelled')

  const third = manager.registerRequest({ sessionId: 's1', fingerprint: 'h', toolName: 'pwsh' })
  const aborted = new AbortController()
  aborted.abort()
  assert.equal(await manager.waitForDecision({ requestId: third.id, timeoutMs: 1000, signal: aborted.signal }), 'cancelled')
})
