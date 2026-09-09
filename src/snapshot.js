/**
 * Git 快照：放行高风险操作前给工作区打一次 checkpoint（`git add -A && git commit`）。
 *
 * 约束：非 git 仓库 / 无变更 / 失败都只记日志，**绝不影响放行**；按会话节流。
 *
 * @module dsh-permission-matrix/snapshot
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const TIMEOUT_MS = 15000

/**
 * 构造快照器。
 * @param {object} config - 插件配置。
 * @param {{info: Function, warn: Function}} logger - 日志。
 * @returns {(session: object, label: string) => Promise<string>} 快照函数（返回结果描述，永不抛出）。
 */
export function makeSnapshot(config, logger) {
  /** 会话 → 上次快照时间（节流）。 */
  const lastAt = new WeakMap()

  return async function snapshot(session, label) {
    if (config.gitSnapshot === false) return 'disabled'
    const cwd = session?.header?.cwd
    if (typeof cwd !== 'string' || cwd === '') return 'no cwd'

    const now = Date.now()
    const previous = lastAt.get(session) ?? 0
    if (now - previous < (config.gitSnapshotIntervalMs ?? 30000)) return 'throttled'

    try {
      await execFileAsync('git', ['rev-parse', '--is-inside-work-tree'], { cwd, timeout: 8000 })
    } catch {
      return 'not a git repo'
    }

    lastAt.set(session, now)
    const stamp = new Date(now).toISOString()
    try {
      await execFileAsync('git', ['add', '-A'], { cwd, timeout: TIMEOUT_MS })
      await execFileAsync('git', ['commit', '-m', `permission-matrix: checkpoint before ${label} @ ${stamp}`], { cwd, timeout: TIMEOUT_MS })
      return 'committed'
    } catch (error) {
      const message = String(error?.message ?? error)
      if (message.includes('nothing to commit') || message.includes('no changes added')) return 'nothing to commit'
      logger?.warn?.(`permission-matrix: git snapshot failed in ${cwd}: ${message}`)
      return 'snapshot failed'
    }
  }
}
