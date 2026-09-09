/**
 * 决策核心单测：规则命中、工作区内放行、受保护目标、中档策略。
 * 运行：node --test tests/
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { applyJudgeVerdict, applyMidPolicy, applyRiskPolicy, classifyByRules, isInside, resolveTarget } from '../src/decide.js'
import { PRESET_IDS, PRESETS, TAKEOVER_DEFAULT } from '../src/presets.js'

const WS = 'C:\\work\\proj'

/** 便捷构造命令类调用。 */
const cmd = (command) => ({ toolName: 'pwsh', args: { command }, workspace: WS })
/** 便捷构造路径类调用。 */
const write = (filePath) => ({ toolName: 'write', args: { file_path: filePath }, workspace: WS })

test('HARD：递归删除根目录 → deny/hard', () => {
  for (const command of ['rm -rf /', 'rm -rf ~/', 'sudo rm -rf /']) {
    const verdict = classifyByRules(cmd(command))
    assert.equal(verdict?.decision, 'deny', command)
    assert.equal(verdict?.risk, 'hard', command)
  }
})

test('HARD：Windows 盘根递归强删 → deny/hard', () => {
  for (const command of ['Remove-Item -Recurse -Force C:\\', 'Remove-Item -Path C:\\ -Recurse -Force']) {
    const verdict = classifyByRules(cmd(command))
    assert.equal(verdict?.decision, 'deny', command)
    assert.equal(verdict?.risk, 'hard', command)
  }
})

test('HARD：格式化 / 提权 / 注册表 / 强推 → deny/hard', () => {
  const cases = ['format C:', 'diskpart', 'sudo apt install foo', 'reg add HKLM\\Software\\X /v y /d 1', 'git push --force origin main', 'netsh advfirewall set allprofiles state off']
  for (const command of cases) {
    const verdict = classifyByRules(cmd(command))
    assert.equal(verdict?.decision, 'deny', command)
    assert.equal(verdict?.risk, 'hard', command)
  }
})

test('误伤回归：Format-Table 等无害 cmdlet 不被硬拒绝（2026-09-09 实测误拦）', () => {
  const safe = ['Get-ChildItem | Format-Table', 'Format-List Name', 'Write-Output "format a table"', 'Get-Date -Format yyyy-MM-dd']
  for (const command of safe) {
    const verdict = classifyByRules(cmd(command))
    assert.notEqual(verdict?.risk, 'hard', `不应硬拒绝: ${command}`)
  }
  // 真正的格式化仍然必须拦下
  assert.equal(classifyByRules(cmd('format D: /fs:ntfs'))?.decision, 'deny')
})

test('HARD：系统目录写入 → deny/hard；普通文本提及不算', () => {
  assert.equal(classifyByRules(cmd('Copy-Item x.dll C:\\Windows\\System32\\x.dll'))?.decision, 'deny')
  assert.equal(classifyByRules(cmd('echo "windows is nice"'))?.decision !== 'deny', true)
})

test('ALLOW：常规 git / 包管理器 / 运行时', () => {
  for (const command of ['git status', 'git add -A', 'npm install', 'node script.js', 'gh pr list']) {
    const verdict = classifyByRules(cmd(command))
    assert.equal(verdict?.decision, 'allow', command)
    assert.equal(verdict?.risk, 'low', command)
  }
})

test('工作区内写入 → allow:in-workspace', () => {
  const verdict = classifyByRules(write('C:\\work\\proj\\src\\a.js'))
  assert.equal(verdict?.decision, 'allow')
  assert.equal(verdict?.rule, 'allow:in-workspace')
})

test('工作区内相对路径按工作区解析 → allow', () => {
  assert.equal(classifyByRules(write('src\\a.js'))?.decision, 'allow')
  assert.equal(classifyByRules(write('sub\\..\\a.js'))?.decision, 'allow')
})

test('受保护目标即使在工作区内 → deny/hard', () => {
  const dshConfig = classifyByRules(write('C:\\work\\proj\\.dsh\\settings.yaml'))
  assert.equal(dshConfig?.decision, 'deny')
  assert.equal(dshConfig?.risk, 'hard')
  const gitMeta = classifyByRules(write('C:\\work\\proj\\.git\\config'))
  assert.equal(gitMeta?.decision, 'deny')
  assert.equal(gitMeta?.rule, 'hard:protected-target', 'HARD 规则未覆盖的受保护目标由结构放行例外兜住')
})

test('工作区外写入未命中规则 → null（交中档策略/裁判）', () => {
  assert.equal(classifyByRules(write('D:\\other\\a.txt')), null)
})

test('未知工具（无字段投影）→ null，不误伤', () => {
  assert.equal(classifyByRules({ toolName: 'univer_execute', args: { code: 'x' }, workspace: WS }), null)
})

test('中档策略三选项（兼容接口）', () => {
  assert.equal(applyMidPolicy('deny').decision, 'deny')
  assert.equal(applyMidPolicy('allow').decision, 'allow')
  assert.equal(applyMidPolicy('ask').decision, 'ask')
  assert.equal(applyMidPolicy('unknown-value').decision, 'deny', '未知值 fail-closed')
})

test('三档风险策略：低/中/高各自可配，极高固定拒绝', () => {
  const policies = { low: 'allow', medium: 'deny', high: 'deny' }
  assert.equal(applyRiskPolicy('low', policies).decision, 'allow')
  assert.equal(applyRiskPolicy('medium', policies).decision, 'deny')
  assert.equal(applyRiskPolicy('high', policies).decision, 'deny')
  // 极高风险不接受任何策略（即使策略表被改成放行）
  assert.equal(applyRiskPolicy('hard', { low: 'allow', medium: 'allow', high: 'allow' }).decision, 'deny')
  assert.equal(applyRiskPolicy('hard', { low: 'allow', medium: 'allow', high: 'allow' }).rule, 'hard-boundary')
  // 三档都可改成转人工
  assert.equal(applyRiskPolicy('low', { low: 'ask' }).decision, 'ask')
  assert.equal(applyRiskPolicy('high', { high: 'ask' }).decision, 'ask')
  // 缺失或非法值 fail-closed
  assert.equal(applyRiskPolicy('medium', {}).decision, 'deny')
  assert.equal(applyRiskPolicy('high', { high: 'weird' }).decision, 'deny')
})

test('裁判结论映射为风险级别 → 策略', () => {
  const policies = { low: 'allow', medium: 'deny', high: 'deny' }
  assert.equal(applyJudgeVerdict('allow', policies).decision, 'allow')
  assert.equal(applyJudgeVerdict('allow', policies).risk, 'low')
  assert.equal(applyJudgeVerdict('deny', policies).decision, 'deny')
  assert.equal(applyJudgeVerdict('deny', policies).risk, 'high')
  assert.equal(applyJudgeVerdict('unsure', policies).decision, 'deny')
  assert.equal(applyJudgeVerdict('unsure', policies).risk, 'medium')
  // 策略可覆盖
  assert.equal(applyJudgeVerdict('unsure', { medium: 'ask' }).decision, 'ask')
  assert.equal(applyJudgeVerdict('deny', { high: 'ask' }).decision, 'ask')
  assert.equal(applyJudgeVerdict('allow', { low: 'deny' }).decision, 'deny')
})

test('路径判定：isInside / resolveTarget', () => {
  assert.equal(isInside('C:\\work\\proj\\a', WS), true)
  assert.equal(isInside('C:\\work\\proj', WS), true)
  assert.equal(isInside('C:\\work\\projX\\a', WS), false, '前缀相同但不是子目录')
  assert.equal(isInside('D:\\a', WS), false)
  assert.equal(resolveTarget('src/a.js', WS), 'C:\\work\\proj\\src\\a.js')
  assert.equal(resolveTarget('', WS), '')
})

test('预设表：9 项、id 唯一、审批值合法', () => {
  assert.equal(PRESETS.length, 9)
  assert.equal(new Set(PRESET_IDS).size, 9)
  for (const preset of PRESETS) {
    assert.ok(['ask', 'never'].includes(preset.approval), `${preset.id} approval 必须是 ask/never`)
    assert.ok(['read-only', 'workspace-write', 'danger-full-access'].includes(preset.sandbox), `${preset.id} sandbox 合法`)
  }
})

test('takeover 默认表只覆盖自动同意 / 自动风险审批档', () => {
  const expected = PRESETS.filter((p) => p.tier === 'auto' || p.tier === 'classify').map((p) => p.id)
  assert.deepEqual(Object.keys(TAKEOVER_DEFAULT).sort(), expected.sort())
  assert.equal(TAKEOVER_DEFAULT['fa-auto'], 'auto-allow')
  assert.equal(TAKEOVER_DEFAULT['ww-classify'], 'classify')
  assert.equal(TAKEOVER_DEFAULT['fa-classify'], 'classify')
})
