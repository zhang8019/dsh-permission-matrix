/**
 * 设置页的 host 半侧：settings 命名空间（`permission-matrix`）+ webServer 同源路由。
 *
 * 数据通道：静态 bundle 的客户端没有 `host.call`（那是动态插件机制），因此设置页
 * 通过 fetch 调用本模块注册的同源路由：
 *   GET  /dsh-permission-matrix/status  当前配置 + 预设表 + 最近裁决
 *   GET  /dsh-permission-matrix/audit   审计尾部（?limit=）
 *   POST /dsh-permission-matrix/set     白名单键写入（热生效）
 *   GET  /dsh-permission-matrix/rules   硬拒绝清单（只读展示）
 *
 * @module dsh-permission-matrix/settings
 */

import { ALLOW_RULES, HARD_DENY_RULES } from './rules.js'
import { PRESETS } from './presets.js'

/** 本插件的 settings 命名空间。 */
export const MATRIX_NS = 'permission-matrix'

/** 可通过设置页写入的键（其余一律拒绝）。 */
export const WRITABLE_KEYS = Object.freeze([
  'riskPolicies',
  'llmJudge',
  'judgeProvider',
  'judgeModel',
  'judgeStages',
  'autoAllowHardGuard',
  'robotDefaultPreset',
  'robotWorkspaces',
  'gitSnapshot',
  'gitSnapshotIntervalMs',
  'auditLog',
  'auditFile',
])

/** 写响应。 */
function sendJson(res, status, payload) {
  const body = JSON.stringify(payload)
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(body)
}

/** 读取请求体。 */
async function readBody(req) {
  const chunks = []
  for await (const chunk of req) chunks.push(chunk)
  return Buffer.concat(chunks).toString('utf8')
}

/**
 * 注册 settings 命名空间。
 * @param {import('@deepseek-ai/cordis').Context} ctx - 插件上下文。
 * @param {object} config - 插件配置。
 * @param {object} schema - Schemastery 配置 schema。
 * @param {(getter: () => object) => void} onSource - 配置源变更回调。
 */
export function installSettings(ctx, config, schema, onSource) {
  let source = () => config
  onSource(source)

  ctx.inject(['settings'], (settingsCtx) => {
    settingsCtx.settings.installSection(ctx, MATRIX_NS, schema, config, {
      setSource: (current) => {
        source = current
        onSource(current)
      },
      onChange: () => {
        onSource(source)
        ctx.logger.info('permission-matrix: settings changed')
      },
    })
  })
}

/**
 * 注册 webServer 同源路由（webServer 服务出现后生效；无 web 的部署自动跳过）。
 * @param {import('@deepseek-ai/cordis').Context} ctx - 插件上下文。
 * @param {object} deps - 依赖。
 * @param {() => object} deps.getConfig - 读取当前配置。
 * @param {() => {recent: (n: number) => object[], file: string}} deps.getAudit - 读取审计器。
 * @returns {void}
 */
export function registerRoutes(ctx, deps) {
  const register = (webCtx) => {
    const webServer = webCtx.get('webServer')
    if (webServer === undefined) return

    webCtx.effect(() => {
      const statusSnapshot = () => {
        const config = deps.getConfig()
        const audit = deps.getAudit()
        return {
          ok: true,
          presets: PRESETS,
          config,
          auditFile: audit.file,
          recent: audit.recent(10),
        }
      }

      const disposers = [
        webServer.register({
          kind: 'exact',
          path: '/dsh-permission-matrix/status',
          handler: async (req, res) => {
            if (req.method !== 'GET') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
            try {
              sendJson(res, 200, statusSnapshot())
            } catch (error) {
              sendJson(res, 500, { ok: false, error: String(error?.message ?? error) })
            }
          },
        }),
        webServer.register({
          kind: 'exact',
          path: '/dsh-permission-matrix/audit',
          handler: async (req, res) => {
            if (req.method !== 'GET') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
            try {
              const url = new URL(req.url ?? '/', 'http://localhost')
              const limit = Number(url.searchParams.get('limit') ?? '20')
              const audit = deps.getAudit()
              sendJson(res, 200, { ok: true, file: audit.file, entries: audit.recent(Number.isFinite(limit) ? limit : 20) })
            } catch (error) {
              sendJson(res, 500, { ok: false, error: String(error?.message ?? error) })
            }
          },
        }),
        webServer.register({
          kind: 'exact',
          path: '/dsh-permission-matrix/rules',
          handler: async (req, res) => {
            if (req.method !== 'GET') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
            // 风险清单只读展示：极高风险（硬拒绝）+ 低风险（允许规则）
            sendJson(res, 200, {
              ok: true,
              readOnly: true,
              hardRules: HARD_DENY_RULES.map((rule) => ({ id: rule.id, note: rule.note, pattern: rule.test.source })),
              allowRules: ALLOW_RULES.map((rule) => ({ id: rule.id, note: rule.note, pattern: rule.test.source })),
            })
          },
        }),
        webServer.register({
          kind: 'exact',
          path: '/dsh-permission-matrix/models',
          handler: async (req, res) => {
            // 已配置的 provider/model 清单，供设置页的裁判模型下拉选择。
            if (req.method !== 'GET') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
            const llm = webCtx.get('llm')
            if (llm === undefined || typeof llm.listProviders !== 'function') {
              return sendJson(res, 503, { ok: false, error: 'llm service unavailable' })
            }
            try {
              const providers = llm.listProviders() ?? []
              const models = []
              for (const entry of providers) {
                const providerId = String(entry?.provider ?? entry?.id ?? entry?.name ?? '')
                if (providerId === '') continue
                let list = []
                try {
                  list = (await llm.listModels(providerId)) ?? []
                } catch {
                  list = []
                }
                for (const model of list) {
                  const id = String(model?.id ?? '')
                  if (id === '') continue
                  models.push({ provider: providerId, model: id, name: String(model?.name ?? id) })
                }
              }
              sendJson(res, 200, { ok: true, models })
            } catch (error) {
              sendJson(res, 500, { ok: false, error: String(error?.message ?? error) })
            }
          },
        }),
        webServer.register({
          kind: 'exact',
          path: '/dsh-permission-matrix/set',
          handler: async (req, res) => {
            if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'method not allowed' })
            ctx.logger.info(`permission-matrix: POST /set received (${req.method})`)
            try {
              const body = JSON.parse((await readBody(req)) || '{}')
              ctx.logger.info(`permission-matrix: POST /set body keys: ${Object.keys(body).join(', ') || '(empty)'}`)
              // 客户端会把整份配置草稿发回来（含 enabled / takeover 等
              // composition 层字段），这里只挑白名单键写入，其余**忽略**而不是
              // 整包拒绝——否则用户改一个策略也会因为附带字段被 400 挡掉。
              const writable = {}
              const ignored = []
              for (const [key, value] of Object.entries(body)) {
                if (WRITABLE_KEYS.includes(key)) writable[key] = value
                else ignored.push(key)
              }
              if (ignored.length > 0) ctx.logger.info(`permission-matrix: POST /set ignoring non-writable keys: ${ignored.join(', ')}`)
              if (Object.keys(writable).length === 0) {
                ctx.logger.warn('permission-matrix: POST /set rejected: no writable key')
                return sendJson(res, 400, { ok: false, error: `no writable key in request (ignored: ${ignored.join(', ')})`, writable: WRITABLE_KEYS })
              }
              const settings = webCtx.get('settings')
              if (settings === undefined) {
                ctx.logger.warn('permission-matrix: POST /set failed: settings service unavailable')
                return sendJson(res, 503, { ok: false, error: 'settings service unavailable; edit the profile cordis.patch.yml instead' })
              }
              // 官方写入路径：{op:'set'|'unset', path:[...], value} 的路径编辑序列
              const ops = Object.entries(writable).map(([key, value]) => ({ op: 'set', path: [key], value }))
              await settings.mutate(MATRIX_NS, ops)
              ctx.logger.info(`permission-matrix: settings updated via web: ${Object.keys(writable).join(', ')}`)
              sendJson(res, 200, statusSnapshot())
            } catch (error) {
              ctx.logger.warn(`permission-matrix: POST /set error: ${String(error?.message ?? error)}`)
              sendJson(res, 400, { ok: false, error: String(error?.message ?? error) })
            }
          },
        }),
        webServer.register({
          kind: 'exact',
          path: '/dsh-permission-matrix/global',
          handler: async (req, res) => {
            // 全局默认预设 = DSH 原生 `permission` 命名空间的 defaultPreset
            // （与 Settings → 权限 同一真源，改这里等于改那里）。
            const settings = webCtx.get('settings')
            if (settings === undefined) return sendJson(res, 503, { ok: false, error: 'settings service unavailable' })
            try {
              if (req.method === 'GET') {
                const section = settings.section?.('permission') ?? {}
                return sendJson(res, 200, { ok: true, defaultPreset: section.defaultPreset ?? null })
              }
              if (req.method === 'POST') {
                const body = JSON.parse((await readBody(req)) || '{}')
                if (typeof body.defaultPreset !== 'string' || body.defaultPreset === '') {
                  return sendJson(res, 400, { ok: false, error: 'defaultPreset must be a non-empty string' })
                }
                await settings.mutate('permission', [{ op: 'set', path: ['defaultPreset'], value: body.defaultPreset }])
                ctx.logger.info(`permission-matrix: global default preset → ${body.defaultPreset}`)
                const section = settings.section?.('permission') ?? {}
                return sendJson(res, 200, { ok: true, defaultPreset: section.defaultPreset ?? body.defaultPreset })
              }
              return sendJson(res, 405, { ok: false, error: 'method not allowed' })
            } catch (error) {
              sendJson(res, 400, { ok: false, error: String(error?.message ?? error) })
            }
          },
        }),
      ]
      return () => {
        for (const dispose of disposers) {
          try {
            dispose?.()
          } catch {
            // 卸载期忽略
          }
        }
      }
    })
    ctx.logger.info('permission-matrix: web control routes registered')
  }

  ctx.inject(['webServer'], register)
}
