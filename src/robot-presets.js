/**
 * 机器人默认预设：社交软件渠道会话（QQ / 微信 / 企微 / Telegram …）用独立的
 * 默认权限预设，与 Web 会话的全局默认区分开。
 *
 * 解耦设计：本模块**不感知任何具体机器人插件**，只按会话工作区匹配
 * `config.robotWorkspaces`。机器人插件卸载后，本插件照常运行，只是不再产生
 * 落在这些工作区的新会话。
 *
 * @module dsh-permission-matrix/robot-presets
 */

import path from 'node:path'

/**
 * 归一化路径比较键（Windows 大小写不敏感）。
 * @param {string} value - 路径。
 * @returns {string} 比较键。
 */
function pathKey(value) {
  return path.resolve(value).replace(/[\\/]+$/, '').toLowerCase()
}

/**
 * 判断工作区是否属于机器人工作区列表（含子目录）。
 * @param {string} cwd - 会话工作区。
 * @param {string[]} robotWorkspaces - 配置的机器人工作区列表。
 * @returns {boolean} 是否匹配。
 */
export function isRobotWorkspace(cwd, robotWorkspaces) {
  if (typeof cwd !== 'string' || cwd === '') return false
  const target = pathKey(cwd)
  return (robotWorkspaces ?? []).some((entry) => {
    if (typeof entry !== 'string' || entry.trim() === '') return false
    const root = pathKey(entry.trim())
    return target === root || target.startsWith(`${root}${path.sep}`)
  })
}

/**
 * 构造机器人默认预设应用器。
 * @param {import('@deepseek-ai/cordis').Context} ctx - 插件上下文。
 * @param {() => object} getConfig - 读取当前配置（settings 可热覆盖）。
 * @returns {{applyTo: (session: object) => boolean, matches: (cwd: string) => boolean}} 应用器。
 */
export function makeRobotDefaults(ctx, getConfig) {
  const matches = (cwd) => isRobotWorkspace(cwd, getConfig().robotWorkspaces)

  /**
   * 若会话属于机器人工作区，则把默认预设切换为 `robotDefaultPreset`。
   * @param {object} session - 会话对象。
   * @returns {boolean} 是否发生了切换。
   */
  const applyTo = (session) => {
    const cwd = session?.header?.cwd
    if (!matches(cwd)) return false

    const service = ctx.get('permissionPresets')
    if (service === undefined || typeof service.set !== 'function') return false

    const target = getConfig().robotDefaultPreset
    try {
      // 已经是目标预设则不动
      if (typeof service.current === 'function' && service.current(session) === target) return false
      service.set(session, target)
      ctx.logger.info(`permission-matrix: robot workspace ${cwd} → preset ${target}`)
      return true
    } catch (error) {
      ctx.logger.warn(`permission-matrix: failed to apply robot preset: ${String(error?.message ?? error)}`)
      return false
    }
  }

  return { applyTo, matches }
}
