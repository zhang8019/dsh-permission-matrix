/**
 * 设置页的 host 半侧：settings 命名空间（`permission-matrix`）+ webServer 同源路由。
 *
 * 数据通道：静态 bundle 的客户端没有 `host.call`（那是动态插件机制），因此设置页
 * 通过 fetch 调用本模块注册的同源路由：
 *   GET  /dsh-permission-matrix/status  当前配置 + 预设表 + 最近裁决
 *   GET  /dsh-permission-matrix/audit   审计尾部（?limit=）
 *   POST /dsh-permission-matrix/set     白名单键写入（热生效）
 *   GET  /dsh-permission-matrix/rules   硬拒绝清单（只读展示）
 *   GET  /dsh-permission-matrix/models  已配置模型清单（裁判模型下拉）
 *   GET  /dsh-permission-matrix/global  全局默认预设（permission 命名空间）
 *   POST /dsh-permission-matrix/global  写全局默认预设
 *   GET  /dsh-permission-matrix/hard-approval   极高风险批准状态（密码是否已设 / 待批准请求 / 令牌）
 *   POST /dsh-permission-matrix/hard-approval   极高风险批准动作（设置密码 / 批准 / 授权下一次）
 *   GET  /dsh-permission-matrix/approve         浏览器直开的批准页（无 JS 依赖，纯表单）
 *
 * 安全约束：`hardApprovalPasswordHash` **永不**出现在任何响应里（`/status` 只回一个
 * `hardApprovalPasswordSet` 布尔），也不在 WRITABLE_KEYS 中——只能经专用动作路由写入。
 *
 * @module dsh-permission-matrix/settings
 */

import { ALLOW_RULES, HARD_DENY_RULES } from './rules.js'
import { PRESETS } from './presets.js'

/** 本插件的 settings 命名空间。 */
export const MATRIX_NS = 'permission-matrix'

/** 可通过设置页写入的键（其余一律拒绝；密码哈希刻意不在其中）。 */
export const WRITABLE_KEYS = Object.freeze([
  'riskPolicies',
  'llmJudge',
  'judgeProvider',
  'judgeModel',
  'judgeStages',
  'autoAllowHardGuard',
  'hardApprovalTtlMs',
  'robotDefaultPreset',
  'robotWorkspaces',
  'gitSnapshot',
  'gitSnapshotIntervalMs',
  'auditLog',
  'auditFile',
])

/**
 * 剥离密钥后再回给浏览器的配置投影。
 * @param {object} config - 当前配置。
 * @returns {object} 可安全回传的配置（含 `hardApprovalPasswordSet` 布尔）。
 */
export function sanitizeConfig(config) {
  const { hardApprovalPasswordHash, ...rest } = config ?? {}
  return Object.assign({}, rest, { hardApprovalPasswordSet: String(hardApprovalPasswordHash ?? '') !== '' })
}

/** HTML 转义（批准页把工具名/目标回显到页面，必须转义）。 */
function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** 成功提示块。 */
function ok(text) {
  return `<p style="color:#0a7d32">${escapeHtml(text)}</p>`
}

/** 失败提示块。 */
function bad(text) {
  return `<p style="color:#c0392b">${escapeHtml(text)}</p>`
}

/**
 * 批准页外壳（无脚本依赖，纯表单）。
 * @param {string} title - 标题。
 * @param {string} body - 已转义的正文 HTML。
 * @returns {string} 完整 HTML。
 */
function pageShell(title, body) {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} — 权限矩阵</title></head>
<body style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.6;color:#222">
<h1 style="font-size:20px">${escapeHtml(title)}</h1>
${body}
<hr style="margin:28px 0;border:none;border-top:1px solid #ddd">
<p style="font-size:12px;color:#888">本页由 dsh-permission-matrix 提供，仅监听本机回环地址；批准口令经 scrypt 校验，明文不会写入磁盘。</p>
</body></html>`
}

/** 写响应。 */
function sendJson(res, status, payload) {
  const body = JSON.stringify(payload)
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(body)
}

/** 写 HTML 响应（批准页用；不依赖任何前端脚本）。 */
function sendHtml(res, status, body) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
  res.end(body)
}

/** 读取请求体。 */
async function readBody(req) {
  const chunks = []
  for await (const chunk of req) chunks.push(chunk)
  return Buffer.concat(chunks).toString('utf8')
}

/**
 * 读取表单体（`application/x-www-form-urlencoded`）。
 * @param {object} req - 请求。
 * @returns {Promise<object>} 字段表。
 */
async function readFormBody(req) {
  const params = new URLSearchParams(await readBody(req))
  const out = {}
  for (const [key, value] of params) out[key] = value
  return out
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
 * @param {() => object} [deps.getHardApproval] - 读取极高风险批准管理器（密码通道）。
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
        const hardApproval = deps.getHardApproval?.()
        return {
          ok: true,
          presets: PRESETS,
          config: sanitizeConfig(config),
          hardApproval: hardApproval?.snapshot?.() ?? null,
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
        webServer.register({
          kind: 'exact',
          path: '/dsh-permission-matrix/hard-approval',
          handler: async (req, res) => {
            // 极高风险批准通道：读状态 / 执行批准动作。密码哈希永不出现在响应里。
            const hardApproval = deps.getHardApproval?.()
            if (hardApproval === undefined) return sendJson(res, 503, { ok: false, error: 'hard approval channel unavailable' })
            try {
              if (req.method === 'GET') return sendJson(res, 200, Object.assign({ ok: true }, hardApproval.snapshot()))
              if (req.method !== 'POST') return sendJson(res, 405, { ok: false, error: 'method not allowed' })

              const body = JSON.parse((await readBody(req)) || '{}')
              const action = String(body.action ?? '')
              const settings = webCtx.get('settings')

              if (action === 'set-password') {
                const prepared = hardApproval.preparePassword({
                  currentPassword: body.currentPassword,
                  newPassword: body.newPassword,
                  confirmPassword: body.confirmPassword,
                })
                if (!prepared.ok) return sendJson(res, 400, Object.assign({ ok: false, error: prepared.error }, hardApproval.snapshot()))
                if (settings === undefined) return sendJson(res, 503, { ok: false, error: 'settings service unavailable' })
                await settings.mutate(MATRIX_NS, [{ op: 'set', path: ['hardApprovalPasswordHash'], value: prepared.hash }])
                ctx.logger.info('permission-matrix: hard approval password set')
                return sendJson(res, 200, Object.assign({ ok: true, message: '批准密码已保存' }, hardApproval.snapshot()))
              }

              if (action === 'clear-password') {
                const verdict = hardApproval.checkPassword(body.password)
                if (!verdict.ok) return sendJson(res, 400, Object.assign({ ok: false, error: verdict.error }, hardApproval.snapshot()))
                if (settings === undefined) return sendJson(res, 503, { ok: false, error: 'settings service unavailable' })
                await settings.mutate(MATRIX_NS, [{ op: 'set', path: ['hardApprovalPasswordHash'], value: '' }])
                ctx.logger.warn('permission-matrix: hard approval password cleared (hard risks now always denied)')
                return sendJson(res, 200, Object.assign({ ok: true, message: '批准密码已清除：极高风险操作将一律拒绝' }, hardApproval.snapshot()))
              }

              if (action === 'approve') {
                const result = hardApproval.approveRequest({ requestId: body.requestId, password: body.password })
                if (!result.ok) return sendJson(res, 400, Object.assign({ ok: false, error: result.error }, hardApproval.snapshot()))
                ctx.logger.info(`permission-matrix: hard approval granted for ${body.requestId}`)
                return sendJson(res, 200, Object.assign({ ok: true, message: '已批准：请让模型重新执行该操作即可放行', grant: result.grant }, hardApproval.snapshot()))
              }

              if (action === 'authorize-next') {
                const result = hardApproval.authorizeNext({ password: body.password })
                if (!result.ok) return sendJson(res, 400, Object.assign({ ok: false, error: result.error }, hardApproval.snapshot()))
                ctx.logger.info('permission-matrix: next hard operation authorized by password')
                return sendJson(res, 200, Object.assign({ ok: true, message: '已授权：下一次极高风险操作将被放行一次', grant: result.grant }, hardApproval.snapshot()))
              }

              if (action === 'dismiss') {
                const removed = hardApproval.dismissRequest(body.requestId)
                return sendJson(res, 200, Object.assign({ ok: true, message: removed ? '已忽略该请求' : '该请求已不存在' }, hardApproval.snapshot()))
              }

              return sendJson(res, 400, { ok: false, error: `unknown action: ${action || '(empty)'}` })
            } catch (error) {
              sendJson(res, 400, { ok: false, error: String(error?.message ?? error) })
            }
          },
        }),
        webServer.register({
          kind: 'exact',
          path: '/dsh-permission-matrix/approve',
          handler: async (req, res) => {
            // 浏览器直开的批准页（纯表单、无需前端脚本）：拦截提示里可以把它给用户。
            const hardApproval = deps.getHardApproval?.()
            if (hardApproval === undefined) return sendHtml(res, 503, pageShell('批准通道不可用', '<p>插件未加载批准通道。</p>'))

            let notice = ''
            if (req.method === 'POST') {
              try {
                const form = await readFormBody(req)
                if (String(form.action ?? '') === 'authorize-next') {
                  const result = hardApproval.authorizeNext({ password: form.password })
                  notice = result.ok ? ok('已授权：下一次极高风险操作将被放行一次。') : bad(result.error)
                } else {
                  const result = hardApproval.approveRequest({ requestId: form.requestId, password: form.password })
                  notice = result.ok ? ok('已批准：请让模型重新执行该操作即可放行。') : bad(result.error)
                }
              } catch (error) {
                notice = bad(String(error?.message ?? error))
              }
            } else if (req.method !== 'GET') {
              return sendHtml(res, 405, pageShell('方法不允许', '<p>仅支持 GET / POST。</p>'))
            }

            const snap = hardApproval.snapshot()
            if (!snap.passwordSet) {
              return sendHtml(
                res,
                200,
                pageShell('极高风险批准', `${notice}<p>尚未设置「极高风险批准密码」，因此没有任何放行路径。</p><p>请到 GUI 的「设置 → 权限矩阵 → 极高风险批准密码」中设置密码。</p>`),
              )
            }
            const rows = snap.pending.length === 0
              ? '<p>当前没有待批准的极高风险请求。</p>'
              : `<form method="post" action="/dsh-permission-matrix/approve">
  ${snap.pending.map((item) => `<label style="display:block;margin:6px 0"><input type="radio" name="requestId" value="${escapeHtml(item.id)}" required> <b>${escapeHtml(item.toolName)}</b> <span style="color:#888">${escapeHtml(item.at)}</span><br><span style="font-family:monospace;font-size:12px;word-break:break-all">${escapeHtml(item.target)}</span></label>`).join('\n  ')}
  <p><input type="password" name="password" placeholder="批准密码" required autocomplete="off" style="padding:6px;width:220px"></p>
  <p><button type="submit">批准选中请求（放行一次）</button></p>
</form>`
            const grantRows = snap.grants.length === 0
              ? ''
              : `<h3>生效中的批准（${snap.grants.length}）</h3><ul>${snap.grants.map((grant) => `<li>${escapeHtml(grant.toolName || '任意极高风险操作')} — 剩余 ${Math.round(grant.expiresInMs / 1000)} 秒</li>`).join('')}</ul>`
            return sendHtml(res, 200, pageShell('极高风险批准', `
${notice}
<h3>待批准的极高风险请求（${snap.pending.length}）</h3>
${rows}
<h3>授权下一次极高风险操作</h3>
<form method="post" action="/dsh-permission-matrix/approve">
  <input type="hidden" name="action" value="authorize-next">
  <p><input type="password" name="password" placeholder="批准密码" required autocomplete="off" style="padding:6px;width:220px"></p>
  <p><button type="submit">授权下一次（不绑定具体操作）</button></p>
</form>
${grantRows}`))
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
