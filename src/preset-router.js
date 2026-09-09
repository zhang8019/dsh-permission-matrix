/**
 * 预设路由：把「当前会话的权限预设」解析为「本插件是否接管、以哪一档接管」。
 *
 * 兼容性说明：`@deepseek-ai/dsh-permission-presets` 0.1.2-rc.1 的
 * `current(session)` 接收 **Session 对象**；社区插件 dsh-auto-classifier 仍按旧
 * 形态传 `session.events`，在新版下会被 try/catch 吞掉并静默失效。本模块按
 * 正确签名调用，并在失败时回退到直接读会话投影 `permissions`。
 *
 * @module dsh-permission-matrix/preset-router
 */

/**
 * 读取会话当前预设 id。
 * @param {import('@deepseek-ai/cordis').Context} ctx - 插件上下文。
 * @param {object} session - 会话对象。
 * @returns {string | null} 预设 id，或 null（无法判定）。
 */
export function currentPresetId(ctx, session) {
  if (session === null || session === undefined) return null

  const service = ctx.get('permissionPresets')
  if (service !== undefined && typeof service.current === 'function') {
    try {
      const value = service.current(session)
      if (typeof value === 'string' && value !== '') return value
    } catch {
      // 旧/新签名不匹配时回退到投影读取
    }
  }

  const projections = ctx.get('sessionProjections')
  if (projections !== undefined && typeof projections.stateOf === 'function') {
    try {
      const state = projections.stateOf(session, 'permissions')
      if (state !== null && typeof state === 'object' && typeof state.preset === 'string') return state.preset
    } catch {
      // 投影不可用时视为无法判定
    }
  }

  return null
}

/**
 * 构造预设路由。
 * @param {import('@deepseek-ai/cordis').Context} ctx - 插件上下文。
 * @param {() => object} getConfig - 读取当前配置（settings 可热覆盖）。
 * @returns {{route: (session: object) => {presetId: string, tier: string} | null, presetIdOf: (session: object) => string | null}} 路由。
 */
export function makePresetRouter(ctx, getConfig) {
  const presetIdOf = (session) => currentPresetId(ctx, session)

  /**
   * 判定本插件在某会话下是否接管。
   * @param {object} session - 会话对象。
   * @returns {{presetId: string, tier: string} | null} 接管信息；null 表示不接管（全程 next()）。
   */
  const route = (session) => {
    const presetId = presetIdOf(session)
    if (presetId === null) return null
    const tier = (getConfig().takeover ?? {})[presetId]
    if (typeof tier !== 'string' || tier === '') return null
    return { presetId, tier }
  }

  return { route, presetIdOf }
}
