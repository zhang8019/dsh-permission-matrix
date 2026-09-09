/**
 * 9 个执行类型预设的机器定义（3 沙箱模式 × 4 审批策略去重后的完整集合）。
 *
 * 这是本插件的单一真源：`cordis.patch.yml` 注入的预设表必须与这里保持一致
 * （tests/presets.test.js 会做交叉校验）。
 *
 * 关键约束：DSH 的 `APPROVAL_POLICIES` 只有 `ask` / `never`。因此
 * 「人工审批 / 自动同意 / 自动风险审批」三档在预设表里都写 `approval: 'ask'`，
 * 由本插件依据当前会话预设名（`tier` 字段）决定实际行为；「自动拒绝」档写
 * `never`，交给 DSH 原生确定性拒绝。
 *
 * @module dsh-permission-matrix/presets
 */

/** DSH 原生沙箱模式（只读这三个值）。 */
export const SANDBOX_MODES = ['read-only', 'workspace-write', 'danger-full-access']

/** 沙箱模式的中文显示名。 */
export const SANDBOX_LABELS = {
  'read-only': '工作区只读权限',
  'workspace-write': '工作区读写权限',
  'danger-full-access': '全电脑读写权限',
}

/**
 * 审批档位（插件内部的分流键，不等于预设表的 approval 值）。
 * - `human`    人工审批：插件不干预，交给浏览器应答者
 * - `auto`     自动同意：插件在 approval/request 返回 allowed-once（带硬拒绝保护）
 * - `classify` 自动风险审批：插件在 tools/pre-execute + approval/request 分级裁决
 * - `deny`     自动拒绝：预设表写 never，DSH 原生拒绝，插件不干预
 */
export const APPROVAL_TIERS = {
  human: '人工审批',
  auto: '自动同意',
  classify: '自动风险审批',
  deny: '自动拒绝',
}

/** 审批档 → 预设表 approval 值。 */
export const TIER_TO_APPROVAL = {
  human: 'ask',
  auto: 'ask',
  classify: 'ask',
  deny: 'never',
}

/**
 * 9 个预设，顺序即下拉菜单顺序。
 * @type {ReadonlyArray<{id: string, sandbox: string, approval: string, tier: string, name: string, description: string}>}
 */
export const PRESETS = Object.freeze([
  {
    id: 'ro-human',
    sandbox: 'read-only',
    approval: 'ask',
    tier: 'human',
    name: '工作区只读权限 + 人工审批',
    description: '只读沙箱：一切写入被拒绝，越权操作需人工批准',
  },
  {
    id: 'ro-deny',
    sandbox: 'read-only',
    approval: 'never',
    tier: 'deny',
    name: '工作区只读权限 + 自动拒绝',
    description: '只读沙箱：写入一律拒绝，无人审批环节（真正只读）',
  },
  {
    id: 'ww-human',
    sandbox: 'workspace-write',
    approval: 'ask',
    tier: 'human',
    name: '工作区读写权限 + 人工审批',
    description: '工作区内可写；越界操作需人工批准',
  },
  {
    id: 'ww-classify',
    sandbox: 'workspace-write',
    approval: 'ask',
    tier: 'classify',
    name: '工作区读写权限 + 自动风险审批',
    description: '工作区内可写；越界与高风险操作按风险分级自动裁决',
  },
  {
    id: 'ww-deny',
    sandbox: 'workspace-write',
    approval: 'never',
    tier: 'deny',
    name: '工作区读写权限 + 自动拒绝',
    description: '工作区内可写；越界操作一律拒绝',
  },
  {
    id: 'fa-human',
    sandbox: 'danger-full-access',
    approval: 'ask',
    tier: 'human',
    name: '全电脑读写权限 + 人工审批',
    description: '文件全放行；需批准的操作交给人工',
  },
  {
    id: 'fa-deny',
    sandbox: 'danger-full-access',
    approval: 'never',
    tier: 'deny',
    name: '全电脑读写权限 + 自动拒绝',
    description: '文件全放行；需批准的操作一律拒绝',
  },
  {
    id: 'fa-auto',
    sandbox: 'danger-full-access',
    approval: 'ask',
    tier: 'auto',
    name: '全电脑读写权限 + 自动同意',
    description: '文件全放行；需批准的操作自动放行（极高风险仍硬拒绝）',
  },
  {
    id: 'fa-classify',
    sandbox: 'danger-full-access',
    approval: 'ask',
    tier: 'classify',
    name: '全电脑读写权限 + 自动风险审批',
    description: '文件全放行；操作按风险分级自动裁决',
  },
])

/** 预设 id 集合，用于校验。 */
export const PRESET_IDS = Object.freeze(PRESETS.map((preset) => preset.id))

/** 默认的 takeover 表：只有自动同意 / 自动风险审批档需要插件接管。 */
export const TAKEOVER_DEFAULT = Object.freeze(
  Object.fromEntries(
    PRESETS.filter((preset) => preset.tier === 'auto' || preset.tier === 'classify').map((preset) => [
      preset.id,
      preset.tier === 'auto' ? 'auto-allow' : 'classify',
    ]),
  ),
)

/**
 * 取一个预设的定义。
 * @param {string} id - 预设 id。
 * @returns {object | undefined} 预设定义。
 */
export function presetById(id) {
  return PRESETS.find((preset) => preset.id === id)
}
