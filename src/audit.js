/**
 * 审计日志：每次裁决写一行 JSONL，可轮转、可按尾部读取。
 *
 * 日志只写文件与进程日志，**不进入模型 transcript**（不新增模型可见输入，
 * 因此无需新增会话事件）。
 *
 * @module dsh-permission-matrix/audit
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

/** 单文件上限（超过即轮转为 .1）。 */
const MAX_BYTES = 1024 * 1024

/**
 * 默认审计文件路径。
 * @returns {string} 绝对路径。
 */
export function defaultAuditFile() {
  return path.join(os.homedir(), '.dsh', 'permission-matrix', 'audit.jsonl')
}

/**
 * 构造审计器。
 * @param {object} config - 插件配置。
 * @returns {{write: (entry: object) => void, recent: (limit: number) => object[], file: string}} 审计器。
 */
export function makeAudit(config) {
  const file = String(config.auditFile ?? '').trim() === '' ? defaultAuditFile() : config.auditFile
  const enabled = config.auditLog !== false

  /** 轮转：超过上限时把当前文件改名为 .1（覆盖旧备份）。 */
  const rotateIfNeeded = () => {
    try {
      const stat = fs.statSync(file)
      if (stat.size > MAX_BYTES) fs.renameSync(file, `${file}.1`)
    } catch {
      // 文件不存在或不可访问 → 无需轮转
    }
  }

  return {
    file,
    /**
     * 追加一条裁决记录（永不抛出）。
     * @param {object} entry - 记录。
     */
    write(entry) {
      if (!enabled) return
      try {
        fs.mkdirSync(path.dirname(file), { recursive: true })
        rotateIfNeeded()
        fs.appendFileSync(file, `${JSON.stringify({ time: new Date().toISOString(), ...entry })}\n`, 'utf8')
      } catch {
        // 审计失败不得影响裁决
      }
    },
    /**
     * 读取最近 N 条记录（供设置页展示）。
     * @param {number} limit - 条数上限。
     * @returns {object[]} 记录（最新在后）。
     */
    recent(limit = 20) {
      try {
        const text = fs.readFileSync(file, 'utf8')
        const lines = text.split('\n').filter((line) => line.trim() !== '')
        return lines.slice(-Math.max(1, Math.min(200, limit))).flatMap((line) => {
          try {
            return [JSON.parse(line)]
          } catch {
            return []
          }
        })
      } catch {
        return []
      }
    },
  }
}
