/**
 * dsh-permission-matrix — 设置页（浏览器半侧，手写 __ModuleLoader__ bundle，无构建步骤）。
 *
 * 数据通道：静态 bundle 客户端没有 `host.call`，因此本页 fetch host 半侧在
 * webServer 上注册的同源路由：
 *   GET  /dsh-permission-matrix/status  配置 + 预设表 + 最近裁决
 *   GET  /dsh-permission-matrix/audit   审计尾部
 *   GET  /dsh-permission-matrix/rules   硬拒绝清单（只读）
 *   GET  /dsh-permission-matrix/global  全局默认预设（permission 命名空间）
 *   POST /dsh-permission-matrix/global  写全局默认预设
 *   POST /dsh-permission-matrix/set     写本插件配置（白名单键）
 *
 * 页面注册为 Settings → 权限矩阵 的独立子页（`settings.section` 槽位）。
 */
window.__ModuleLoader__.load({
	id: 'dsh-permission-matrix/client',
	factory: (require) => {
		'use strict'
		var module = { exports: {} }
		var exports = module.exports

		var react = require('react')
		var BASE = '/dsh-permission-matrix'

		/** 低 / 中 / 高 三档共用的选项（四值：放行 / 拒绝 / 转人工 / 需批准密码）。 */
		var POLICY_OPTIONS = [
			{ value: 'allow', label: '放行' },
			{ value: 'deny', label: '拒绝' },
			{ value: 'ask', label: '转人工（点同意即放行）' },
			{ value: 'password', label: '需批准密码（弹窗输密码）' },
		]

		/** 极高风险档专用选项：只允许拒绝 / 需批准密码（ask 与 password 等价，均为输密码）。 */
		var HARD_POLICY_OPTIONS = [
			{ value: 'deny', label: '拒绝' },
			{ value: 'password', label: '需批准密码（弹窗输密码）' },
			{ value: 'ask', label: '需批准密码（旧值 ask，等价）' },
		]

		/** 风险级别 → 中文名（弹窗与设置页共用）。 */
		var RISK_LABELS = { low: '低风险', medium: '中风险', high: '高风险', hard: '极高风险' }

		var box = { border: '0.5px solid var(--dsw-alias-border-l2)', borderRadius: '12px', padding: '14px 16px', marginBottom: '12px', background: 'var(--dsw-alias-bg-layer-1)' }
		var h2 = { fontSize: '14px', fontWeight: 600, margin: '0 0 4px' }
		var desc = { fontSize: '12px', color: 'var(--dsw-alias-label-tertiary)', margin: '0 0 10px' }
		var row = { display: 'flex', alignItems: 'center', gap: '10px', margin: '8px 0', flexWrap: 'wrap' }
		var label = { fontSize: '13px', minWidth: '150px' }
		var select = { fontSize: '13px', padding: '5px 8px', borderRadius: '8px', border: '0.5px solid var(--dsw-alias-border-l3)', background: 'var(--dsw-alias-bg-module-platform)', color: 'var(--dsw-alias-label-primary)' }
		var input = { fontSize: '13px', padding: '5px 8px', borderRadius: '8px', border: '0.5px solid var(--dsw-alias-border-l3)', background: 'var(--dsw-alias-bg-module-platform)', color: 'var(--dsw-alias-label-primary)', minWidth: '200px' }
		var textarea = { fontSize: '12px', padding: '8px', borderRadius: '8px', border: '0.5px solid var(--dsw-alias-border-l3)', background: 'var(--dsw-alias-bg-module-platform)', color: 'var(--dsw-alias-label-primary)', width: '100%', minHeight: '64px', fontFamily: 'monospace' }
		var btn = { fontSize: '13px', padding: '6px 14px', borderRadius: '8px', border: '0.5px solid var(--dsw-alias-border-l3)', background: 'var(--dsw-alias-bg-module-platform)', color: 'var(--dsw-alias-label-primary)', cursor: 'pointer' }
		var badge = { fontSize: '11px', padding: '2px 7px', borderRadius: '999px', background: 'var(--dsw-alias-bg-module-platform)', color: 'var(--dsw-alias-label-secondary)', marginRight: '6px' }
		var mono = { fontFamily: 'monospace', fontSize: '11px', color: 'var(--dsw-alias-label-secondary)', wordBreak: 'break-all' }

		function useApi() {
			var s = react.useState({ status: 'loading', data: null, error: null, globalPreset: null, hardRules: [], allowRules: [], models: [] })
			var state = s[0]
			var setState = s[1]
			var patch = react.useCallback(function (next) {
				setState(function (prev) {
					return Object.assign({}, prev, next)
				})
			}, [])
			var reload = react.useCallback(function () {
				patch({ status: 'loading', error: null })
				Promise.all([
					fetch(BASE + '/status').then(function (r) { return r.json() }),
					fetch(BASE + '/global').then(function (r) { return r.json() }).catch(function () { return {} }),
					fetch(BASE + '/rules').then(function (r) { return r.json() }).catch(function () { return {} }),
					fetch(BASE + '/models').then(function (r) { return r.json() }).catch(function () { return {} }),
				])
					.then(function (all) {
						patch({
							status: 'ready',
							data: all[0],
							globalPreset: all[1] && all[1].defaultPreset,
							hardRules: (all[2] && all[2].hardRules) || [],
							allowRules: (all[2] && all[2].allowRules) || [],
							models: (all[3] && all[3].models) || [],
						})
					})
					.catch(function (error) {
						patch({ status: 'error', error: String(error && error.message ? error.message : error) })
					})
			}, [patch])
			react.useEffect(function () { reload() }, [reload])
			return { state: state, patch: patch, reload: reload }
		}

		function post(path, body) {
			return fetch(BASE + path, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(body),
			})
				.then(function (r) {
					return r.json().catch(function () {
						return { ok: false, error: 'HTTP ' + r.status + ' ' + (r.statusText || '') }
					})
				})
				.catch(function (error) {
					return { ok: false, error: String(error && error.message ? error.message : error) }
				})
		}

		function Panel() {
			var api = useApi()
			var state = api.state
			var data = state.data || {}
			var config = data.config || {}
			var presets = data.presets || []
			var [draft, setDraft] = react.useState(null)
			var [msg, setMsg] = react.useState(null)
			var [showRules, setShowRules] = react.useState(true)
			var [pwCurrent, setPwCurrent] = react.useState('')
			var [pwNew, setPwNew] = react.useState('')
			var [pwConfirm, setPwConfirm] = react.useState('')
			var [approvePw, setApprovePw] = react.useState('')
			var [passwordMsg, setPasswordMsg] = react.useState(null)

			// 批准状态轮询：极高风险被拦截时，本页无需手动刷新就会出现「待批准请求」。
			react.useEffect(function () {
				var timer = setInterval(function () {
					fetch(BASE + '/password-approval')
						.then(function (r) { return r.json() })
						.then(function (res) { if (res && res.ok) api.patch({ passwordApproval: res }) })
						.catch(function () {})
				}, 3000)
				return function () { clearInterval(timer) }
			}, [api.patch])

			var effective = draft || config
			var set = function (key, value) {
				setDraft(Object.assign({}, effective, { [key]: value }))
			}

			if (state.status === 'loading' && !state.data) return react.createElement('div', { style: desc }, '加载中…')
			if (state.status === 'error') return react.createElement('div', { style: { color: 'var(--dsw-alias-state-error-primary)', fontSize: '13px' } }, '加载失败：' + state.error)

			var presetOptions = presets.map(function (p) {
				return react.createElement('option', { key: p.id, value: p.id }, p.name)
			})

			// 已配置模型（来自 host 的 /models 路由）→ 裁判模型的联级下拉
			var models = state.models || []
			var providers = []
			models.forEach(function (m) { if (providers.indexOf(m.provider) < 0) providers.push(m.provider) })
			var modelsOfProvider = models.filter(function (m) { return m.provider === (effective.judgeProvider || '') })

			var save = function () {
				if (!draft) return
				var payload = {}
				Object.keys(draft).forEach(function (key) {
					if (key !== 'presets') payload[key] = draft[key]
				})
				post('/set', payload).then(function (res) {
					if (res && res.ok) {
						setMsg({ kind: 'ok', text: '已保存并热生效' })
						setDraft(null)
						api.reload()
					} else {
						setMsg({ kind: 'error', text: (res && res.error) || '保存失败' })
					}
				})
			}

			var saveGlobal = function (value) {
				post('/global', { defaultPreset: value }).then(function (res) {
					if (res && res.ok) {
						setMsg({ kind: 'ok', text: '全局默认预设已更新' })
						api.patch({ globalPreset: res.defaultPreset })
					} else {
						setMsg({ kind: 'error', text: (res && res.error) || '更新失败' })
					}
				})
			}

			var children = []

			children.push(react.createElement('h2', { key: 'title', style: h2 }, '权限矩阵'))
			children.push(react.createElement('p', { key: 'desc', style: desc },
				'3 种沙箱 × 4 种审批 = 9 个执行类型。人工审批 / 自动同意 / 自动风险审批三档在预设表里都写 ask，由本插件按当前预设分流；自动拒绝档由 DSH 原生拒绝。'))
			if (msg) {
				children.push(react.createElement('p', {
					key: 'msg',
					style: { fontSize: '12px', color: msg.kind === 'ok' ? 'var(--dsw-alias-state-success-primary)' : 'var(--dsw-alias-state-error-primary)' },
				}, msg.text))
			}

			// ── 两个默认预设 ──────────────────────────────────────────────
			children.push(react.createElement('div', { key: 'defaults', style: box }, [
				react.createElement('h2', { key: 'h', style: h2 }, '默认预设'),
				react.createElement('p', { key: 'p', style: desc }, '全局默认作用于新会话；机器人默认作用于社交渠道会话（按工作区匹配）。会话内可用 /permission 临时切换。'),
				react.createElement('div', { key: 'r1', style: row }, [
					react.createElement('span', { key: 'l', style: label }, '全局默认预设'),
					react.createElement('select', {
						key: 's',
						style: select,
						value: state.globalPreset || '',
						onChange: function (e) { saveGlobal(e.target.value) },
					}, [react.createElement('option', { key: '', value: '' }, '（未设置）')].concat(presetOptions)),
				]),
				react.createElement('div', { key: 'r2', style: row }, [
					react.createElement('span', { key: 'l', style: label }, 'LLM 机器人默认预设'),
					react.createElement('select', {
						key: 's',
						style: select,
						value: effective.robotDefaultPreset || '',
						onChange: function (e) { set('robotDefaultPreset', e.target.value) },
					}, presetOptions),
				]),
				react.createElement('div', { key: 'r3', style: { marginTop: '8px' } }, [
					react.createElement('div', { key: 'l', style: Object.assign({}, label, { marginBottom: '4px' }) }, '机器人工作区（每行一个绝对路径）'),
					react.createElement('textarea', {
						key: 't',
						style: textarea,
						value: (effective.robotWorkspaces || []).join('\n'),
						onChange: function (e) {
							set('robotWorkspaces', e.target.value.split('\n').map(function (x) { return x.trim() }).filter(Boolean))
						},
					}),
				]),
			]))

			// ── 风险分类 ──────────────────────────────────────────────────
			var policyOptions = POLICY_OPTIONS.map(function (o) {
				return react.createElement('option', { key: o.value, value: o.value }, o.label)
			})
			var hardOptions = HARD_POLICY_OPTIONS.map(function (o) {
				return react.createElement('option', { key: o.value, value: o.value }, o.label)
			})
			var riskPolicies = effective.riskPolicies || {}
			var riskRow = function (levelKey, title, hint, options) {
				return react.createElement('div', { key: 'rp-' + levelKey, style: row }, [
					react.createElement('span', { key: 'l', style: label }, title),
					react.createElement('select', {
						key: 's',
						style: Object.assign({}, select, { minWidth: '160px' }),
						value: riskPolicies[levelKey] || (levelKey === 'low' ? 'allow' : 'deny'),
						onChange: function (e) {
							var next = Object.assign({}, riskPolicies)
							next[levelKey] = e.target.value
							set('riskPolicies', next)
						},
					}, options || policyOptions),
					react.createElement('span', { key: 'h', style: desc }, hint),
				])
			}
			children.push(react.createElement('div', { key: 'risk', style: box }, [
				react.createElement('h2', { key: 'h', style: h2 }, '自动风险审批 · 四档策略'),
				react.createElement('p', { key: 'p', style: desc }, '低 / 中 / 高 三档各自可选「放行 / 拒绝 / 转人工 / 需批准密码」。选「需批准密码」后，该档操作会挂起并由本文下方「批准密码」弹窗/区块要求输入密码，输对才放行（与转人工的区别：转人工点一下同意即可，密码批准必须知道口令）。极高风险（下面的硬拒绝清单）只允许「拒绝」或「需批准密码」。'),
				riskRow('low', '低风险策略', '允许规则命中、工作区内操作、裁判判定安全 → 默认放行'),
				riskRow('medium', '中风险策略', '规则未命中、裁判不确定 → 默认拒绝'),
				riskRow('high', '高风险策略', '裁判判定危险、非盘根递归删除、git push → 默认拒绝'),
				riskRow('hard', '极高风险策略', '删根 / 格式化 / 提权 / 凭据 / 系统级包安装等 → 默认拒绝；password = 输密码放行', hardOptions),
				react.createElement('div', { key: 'r2', style: row }, [
					react.createElement('label', { key: 'l', style: Object.assign({}, label, { display: 'flex', gap: '6px', alignItems: 'center' }) }, [
						react.createElement('input', {
							key: 'c',
							type: 'checkbox',
							checked: effective.llmJudge !== false,
							onChange: function (e) { set('llmJudge', e.target.checked) },
						}),
						'启用 LLM 裁判',
					]),
					react.createElement('span', { key: 'h', style: desc }, '规则未命中时由模型语义裁决；留空模型则跟随当前会话'),
				]),
				react.createElement('div', { key: 'r3', style: row }, [
					react.createElement('span', { key: 'l', style: label }, '裁判模型'),
					react.createElement('select', {
						key: 'p',
						style: Object.assign({}, select, { minWidth: '180px' }),
						value: effective.judgeProvider || '',
						onChange: function (e) {
							var value = e.target.value
							setDraft(Object.assign({}, effective, { judgeProvider: value, judgeModel: '' }))
						},
					}, [react.createElement('option', { key: '', value: '' }, '（跟随当前会话模型）')].concat(
						providers.map(function (p) { return react.createElement('option', { key: p, value: p }, p) }),
					)),
					react.createElement('select', {
						key: 'm',
						style: Object.assign({}, select, { minWidth: '200px' }),
						value: effective.judgeModel || '',
						disabled: !effective.judgeProvider,
						onChange: function (e) { set('judgeModel', e.target.value) },
					}, [react.createElement('option', { key: '', value: '' }, effective.judgeProvider ? '（该 provider 默认）' : '—')].concat(
						modelsOfProvider.map(function (m) { return react.createElement('option', { key: m.model, value: m.model }, m.name === m.model ? m.model : m.name + ' (' + m.model + ')') }),
					)),
					react.createElement('select', { key: 's', style: select, value: effective.judgeStages || 'both', onChange: function (e) { set('judgeStages', e.target.value) } }, [
						react.createElement('option', { key: 'both', value: 'both' }, '两阶段（默认）'),
						react.createElement('option', { key: 'fast', value: 'fast' }, '仅快速过滤'),
						react.createElement('option', { key: 'thinking', value: 'thinking' }, '仅思考复审'),
					]),
				]),
				react.createElement('div', { key: 'r3b', style: { marginLeft: '150px', marginTop: '-4px' } },
					react.createElement('span', { key: 'h', style: desc },
						state.models.length > 0
							? '共 ' + state.models.length + ' 个已配置模型可选；留空 provider 则跟随当前会话模型'
							: '未能读取已配置模型（可留空 provider 跟随当前会话）')),
				react.createElement('div', { key: 'r4', style: row }, [
					react.createElement('label', { key: 'l', style: Object.assign({}, label, { display: 'flex', gap: '6px', alignItems: 'center' }) }, [
						react.createElement('input', {
							key: 'c',
							type: 'checkbox',
							checked: effective.autoAllowHardGuard !== false,
							onChange: function (e) { set('autoAllowHardGuard', e.target.checked) },
						}),
						'自动同意档的硬拒绝保护',
					]),
				]),
				react.createElement('div', { key: 'r5', style: row }, [
					react.createElement('label', { key: 'l', style: Object.assign({}, label, { display: 'flex', gap: '6px', alignItems: 'center' }) }, [
						react.createElement('input', {
							key: 'c',
							type: 'checkbox',
							checked: effective.gitSnapshot !== false,
							onChange: function (e) { set('gitSnapshot', e.target.checked) },
						}),
						'Git 快照',
					]),
					react.createElement('input', {
						key: 'i',
						style: Object.assign({}, input, { minWidth: '120px' }),
						type: 'number',
						value: effective.gitSnapshotIntervalMs || 30000,
						onChange: function (e) { set('gitSnapshotIntervalMs', Number(e.target.value) || 30000) },
					}),
					react.createElement('span', { key: 'h', style: desc }, '毫秒（节流）'),
				]),
				react.createElement('div', { key: 'r6', style: row }, [
					react.createElement('button', { key: 'b', style: btn, onClick: save, disabled: !draft }, '保存'),
					react.createElement('button', {
						key: 'b2',
						style: btn,
						onClick: function () { setDraft(null); setMsg(null) },
						disabled: !draft,
					}, '放弃改动'),
					react.createElement('button', { key: 'b3', style: btn, onClick: function () { setShowRules(!showRules) } }, showRules ? '隐藏风险清单' : '展开风险清单（只读）'),
				]),
				showRules ? react.createElement('div', { key: 'rules', style: { marginTop: '12px' } }, [
					react.createElement('div', { key: 'h1', style: Object.assign({}, h2, { fontSize: '13px' }) }, '极高风险 · 硬拒绝清单（' + state.hardRules.length + ' 条，只读不可编辑）'),
					react.createElement('div', { key: 'l1' }, state.hardRules.map(function (r) {
						return react.createElement('div', { key: r.id, style: { marginBottom: '6px' } }, [
							react.createElement('span', { key: 'n', style: badge }, r.note),
							react.createElement('span', { key: 'p', style: mono }, r.pattern),
						])
					})),
					react.createElement('div', { key: 'h2', style: Object.assign({}, h2, { fontSize: '13px', marginTop: '12px' }) }, '低风险 · 允许清单（' + state.allowRules.length + ' 条，只读）'),
					react.createElement('div', { key: 'l2' }, state.allowRules.map(function (r) {
						return react.createElement('div', { key: r.id, style: { marginBottom: '6px' } }, [
							react.createElement('span', { key: 'n', style: badge }, r.note),
							react.createElement('span', { key: 'p', style: mono }, r.pattern),
						])
					})),
				]) : null,
			]))

			// ── 批准密码（密码批准通道） ──────────────────────────────────
			var pwState = state.passwordApproval || {}
			var passwordPending = pwState.pending || []
			var passwordGrants = pwState.grants || []
			var pwSet = pwState.passwordSet === true || config.approvalPasswordSet === true

			var passwordAction = function (payload) {
				return post('/password-approval', payload).then(function (res) {
					if (res && res.ok) setPasswordMsg({ kind: 'ok', text: res.message || '已生效' })
					else setPasswordMsg({ kind: 'error', text: (res && res.error) || '操作失败' })
					if (res && (res.ok === true || Array.isArray(res.pending))) api.patch({ passwordApproval: res })
					return res
				})
			}
			var doSetPassword = function () {
				passwordAction({ action: 'set-password', currentPassword: pwCurrent, newPassword: pwNew, confirmPassword: pwConfirm }).then(function (res) {
					if (res && res.ok) {
						setPwCurrent('')
						setPwNew('')
						setPwConfirm('')
					}
				})
			}
			var doClearPassword = function () {
				if (!pwCurrent) {
					setPasswordMsg({ kind: 'error', text: '清除密码需先输入当前批准密码' })
					return
				}
				passwordAction({ action: 'clear-password', password: pwCurrent }).then(function (res) {
					if (res && res.ok) setPwCurrent('')
				})
			}
			var doApprove = function (requestId) {
				if (!approvePw) {
					setPasswordMsg({ kind: 'error', text: '请先输入批准密码' })
					return
				}
				passwordAction({ action: 'approve', requestId: requestId, password: approvePw }).then(function (res) {
					if (res && res.ok) setApprovePw('')
				})
			}
			var doAuthorizeNext = function () {
				if (!approvePw) {
					setPasswordMsg({ kind: 'error', text: '请先输入批准密码' })
					return
				}
				passwordAction({ action: 'authorize-next', password: approvePw }).then(function (res) {
					if (res && res.ok) setApprovePw('')
				})
			}
			var passwordMsgStyle = {
				fontSize: '12px',
				color: passwordMsg && passwordMsg.kind === 'ok' ? 'var(--dsw-alias-state-success-primary)' : 'var(--dsw-alias-state-error-primary)',
			}

			children.push(react.createElement('div', { key: 'hardpw', style: box }, [
				react.createElement('h2', { key: 'h', style: h2 }, '批准密码'),
				react.createElement('p', { key: 'p', style: desc },
					'任何风险档在策略里选「需批准密码」后，该档操作会被挂起，并要求输入本密码才放行：拦下后这里（或密码弹窗、浏览器打开 http://127.0.0.1:<Web端口>/dsh-permission-matrix/approve）输入密码批准即可。未设置密码 ⇒ 所有「需批准密码」档一律拒绝。'),
				react.createElement('div', { key: 'status', style: row }, [
					react.createElement('span', { key: 'l', style: label }, '批准密码状态'),
					react.createElement('span', {
						key: 'v',
						style: Object.assign({}, badge, { color: pwSet ? 'var(--dsw-alias-state-success-primary)' : 'var(--dsw-alias-state-error-primary)' }),
					}, pwSet ? '已设置' : '未设置（需密码的档位一律拒绝）'),
					react.createElement('span', { key: 'h', style: desc }, '口令以 scrypt 哈希存储：明文不落盘、不回传页面'),
				]),
				react.createElement('div', { key: 'setpw', style: row }, [
					pwSet ? react.createElement('input', {
						key: 'c',
						style: Object.assign({}, input, { minWidth: '150px' }),
						type: 'password',
						placeholder: '当前批准密码',
						value: pwCurrent,
						autoComplete: 'off',
						onChange: function (e) { setPwCurrent(e.target.value) },
					}) : null,
					react.createElement('input', {
						key: 'n',
						style: Object.assign({}, input, { minWidth: '150px' }),
						type: 'password',
						placeholder: '新批准密码（≥6 位）',
						value: pwNew,
						autoComplete: 'new-password',
						onChange: function (e) { setPwNew(e.target.value) },
					}),
					react.createElement('input', {
						key: 'n2',
						style: Object.assign({}, input, { minWidth: '150px' }),
						type: 'password',
						placeholder: '再输一次',
						value: pwConfirm,
						autoComplete: 'new-password',
						onChange: function (e) { setPwConfirm(e.target.value) },
					}),
					react.createElement('button', { key: 'b', style: btn, onClick: doSetPassword }, pwSet ? '修改密码' : '设置密码'),
					pwSet ? react.createElement('button', { key: 'b2', style: btn, onClick: doClearPassword }, '清除密码') : null,
				]),
				react.createElement('div', { key: 'ttl', style: row }, [
					react.createElement('span', { key: 'l', style: label }, '批准有效期'),
					react.createElement('input', {
						key: 'i',
						style: Object.assign({}, input, { minWidth: '120px' }),
						type: 'number',
						value: effective.approvalPasswordTtlMs || 300000,
						onChange: function (e) { set('approvalPasswordTtlMs', Number(e.target.value) || 300000) },
					}),
					react.createElement('span', { key: 'h', style: desc }, '毫秒；批准后在此窗口内放行一次（用后即焚）'),
					react.createElement('button', { key: 'b', style: btn, onClick: save, disabled: !draft }, '保存有效期'),
				]),
				passwordMsg ? react.createElement('p', { key: 'hm', style: passwordMsgStyle }, passwordMsg.text) : null,
				react.createElement('div', { key: 'pend', style: { marginTop: '10px' } }, [
					react.createElement('div', { key: 'h', style: Object.assign({}, h2, { fontSize: '13px' }) }, '待批准的请求（' + passwordPending.length + '）'),
					passwordPending.length === 0
						? react.createElement('p', { key: 'e', style: desc }, '暂无。选了「需批准密码」的操作被挂起后会自动出现在这里（每 3 秒刷新）。')
						: react.createElement('div', { key: 'rows' }, passwordPending.map(function (item) {
							return react.createElement('div', {
								key: item.id,
								style: { border: '0.5px solid var(--dsw-alias-border-l2)', borderRadius: '8px', padding: '8px 10px', margin: '6px 0' },
							}, [
								react.createElement('div', { key: 'a', style: { fontSize: '12px' } }, [
									react.createElement('span', { key: 'b', style: badge }, item.toolName),
									react.createElement('span', { key: 't', style: desc }, item.at),
									react.createElement('span', { key: 'i', style: Object.assign({}, desc, { fontFamily: 'monospace' }) }, item.id),
								]),
								react.createElement('div', { key: 't2', style: mono }, item.target || '（无目标文本）'),
								react.createElement('button', { key: 'b2', style: btn, onClick: function () { doApprove(item.id) } }, '批准（放行一次）'),
							])
						})),
				]),
				react.createElement('div', { key: 'appr', style: row }, [
					react.createElement('input', {
						key: 'p',
						style: Object.assign({}, input, { minWidth: '150px' }),
						type: 'password',
						placeholder: '批准密码',
						value: approvePw,
						autoComplete: 'off',
						onChange: function (e) { setApprovePw(e.target.value) },
					}),
					react.createElement('button', { key: 'b', style: btn, onClick: doAuthorizeNext }, '授权下一次需密码的操作'),
					react.createElement('span', { key: 'h', style: desc }, '不绑定具体操作：下一次需密码的操作放行一次'),
				]),
				passwordGrants.length > 0 ? react.createElement('div', { key: 'g', style: { marginTop: '8px' } }, [
					react.createElement('div', { key: 'h', style: Object.assign({}, h2, { fontSize: '13px' }) }, '生效中的批准（' + passwordGrants.length + '）'),
					react.createElement('div', { key: 'l' }, passwordGrants.map(function (grant) {
						return react.createElement('div', { key: grant.id, style: { fontSize: '12px' } },
							(grant.toolName || '任意需密码操作') + ' — 剩余 ' + Math.round((grant.expiresInMs || 0) / 1000) + ' 秒（' + grant.id + '）')
					})),
				]) : null,
			]))

			// ── 预设表 ────────────────────────────────────────────────────
			children.push(react.createElement('div', { key: 'presets', style: box }, [
				react.createElement('h2', { key: 'h', style: h2 }, '9 个执行类型'),
				react.createElement('p', { key: 'p', style: desc }, '下拉菜单顺序即下表顺序。'),
				react.createElement('div', { key: 'list' }, presets.map(function (p) {
					return react.createElement('div', { key: p.id, style: { margin: '6px 0', fontSize: '12px' } }, [
						react.createElement('span', { key: 'b', style: badge }, p.id),
						react.createElement('span', { key: 'n', style: { fontWeight: 500 } }, p.name),
						react.createElement('div', { key: 'd', style: desc }, p.sandbox + ' + ' + p.approval + ' — ' + p.description),
					])
				})),
			]))

			// ── 最近裁决 ──────────────────────────────────────────────────
			children.push(react.createElement('div', { key: 'audit', style: box }, [
				react.createElement('h2', { key: 'h', style: h2 }, '最近裁决'),
				react.createElement('p', { key: 'p', style: desc }, '审计文件：' + (data.auditFile || '—')),
				(Array.isArray(data.recent) && data.recent.length > 0)
					? react.createElement('div', { key: 'rows' }, data.recent.slice().reverse().map(function (e, i) {
						return react.createElement('div', { key: i, style: { fontSize: '11px', fontFamily: 'monospace', margin: '4px 0' } },
							[e.time, e.preset, e.tool, e.risk, e.rule, e.decision, e.outcome].filter(Boolean).join('  |  '))
					}))
					: react.createElement('p', { key: 'empty', style: desc }, '暂无记录（插件只在「自动同意 / 自动风险审批」档写审计）。'),
			]))

			return react.createElement('div', { style: { width: '100%', maxWidth: '760px' } }, children)
		}

		/**
		 * 极高风险批准弹窗（注册进 `shell.overlay`，浮在整个应用之上）。
		 *
		 * 有「待批准请求」时才渲染：输入批准密码点「批准」→ 被挂起的调用**立即执行**
		 * （host 侧审批瀑布正等这个密码），不需要模型重试；点「忽略」按拒绝处理。
		 * 没有待批准请求时返回 null —— 不占位，也不影响点击（overlay 默认点击穿透）。
		 */
		function PasswordApprovalPrompt() {
			var s = react.useState({ pending: [], passwordSet: false, grants: [] })
			var state = s[0]
			var setState = s[1]
			var p = react.useState('')
			var password = p[0]
			var setPassword = p[1]
			var m = react.useState(null)
			var msg = m[0]
			var setMsg = m[1]
			var b = react.useState(false)
			var busy = b[0]
			var setBusy = b[1]

			react.useEffect(function () {
				var alive = true
				var tick = function () {
					fetch(BASE + '/password-approval')
						.then(function (r) { return r.json() })
						.then(function (res) { if (alive && res && res.ok) setState(res) })
						.catch(function () {})
				}
				tick()
				var timer = setInterval(tick, 2000)
				return function () {
					alive = false
					clearInterval(timer)
				}
			}, [])

			var pending = state.pending || []
			if (pending.length === 0) return null

			var submit = function (body) {
				if (busy) return
				setBusy(true)
				fetch(BASE + '/password-approval', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify(body),
				})
					.then(function (r) { return r.json() })
					.then(function (res) {
						if (res && res.ok) {
							setMsg({ kind: 'ok', text: res.message || '已批准，本次调用已放行' })
							setPassword('')
						} else {
							setMsg({ kind: 'error', text: (res && res.error) || '操作失败' })
						}
						if (res && Array.isArray(res.pending)) setState(res)
					})
					.catch(function (error) {
						setMsg({ kind: 'error', text: String(error && error.message ? error.message : error) })
					})
					.then(function () { setBusy(false) })
			}
			var approve = function (requestId) {
				if (!password) {
					setMsg({ kind: 'error', text: '请输入批准密码' })
					return
				}
				submit({ action: 'approve', requestId: requestId, password: password })
			}
			var ignore = function (requestId) { submit({ action: 'dismiss', requestId: requestId }) }

			var card = {
				pointerEvents: 'auto',
				width: '560px',
				maxWidth: '92vw',
				maxHeight: '80vh',
				overflowY: 'auto',
				background: 'var(--dsw-alias-bg-layer-1)',
				border: '0.5px solid var(--dsw-alias-border-l2)',
				borderRadius: '14px',
				boxShadow: '0 14px 44px rgba(0,0,0,.30)',
				padding: '18px 20px',
			}
			var msgStyle = {
				fontSize: '12px',
				margin: '8px 0 0',
				color: msg && msg.kind === 'ok' ? 'var(--dsw-alias-state-success-primary)' : 'var(--dsw-alias-state-error-primary)',
			}
			var chip = { fontSize: '11px', padding: '1px 6px', borderRadius: '999px', background: 'var(--dsw-alias-bg-module-platform)', color: 'var(--dsw-alias-label-secondary)' }

			return react.createElement('div', {
				style: { position: 'fixed', inset: '0', zIndex: 4000, display: 'flex', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' },
			}, react.createElement('div', { style: card }, [
				react.createElement('div', { key: 'h', style: { fontSize: '15px', fontWeight: 600, marginBottom: '6px' } }, '操作待批准（需密码）'),
				react.createElement('div', { key: 'd', style: { fontSize: '12px', color: 'var(--dsw-alias-label-tertiary)', marginBottom: '10px' } },
					state.passwordSet
						? '下列调用已挂起等放行：输入批准密码点「批准」即立即执行；点「忽略」按拒绝处理。'
						: '尚未设置「批准密码」，无法放行：请先到 设置 → 权限矩阵 → 批准密码 设置密码。'),
				react.createElement('div', { key: 'list' }, pending.map(function (item) {
					return react.createElement('div', {
						key: item.id,
						style: { border: '0.5px solid var(--dsw-alias-border-l2)', borderRadius: '10px', padding: '10px 12px', marginBottom: '8px' },
					}, [
						react.createElement('div', { key: 'top', style: { display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px', flexWrap: 'wrap' } }, [
							react.createElement('span', { key: 't', style: { fontSize: '13px', fontWeight: 600 } }, item.toolName),
							item.risk ? react.createElement('span', { key: 'r', style: chip }, RISK_LABELS[item.risk] || item.risk) : null,
							item.waiting ? react.createElement('span', { key: 'w', style: chip }, '等待中') : null,
							react.createElement('span', { key: 'id', style: Object.assign({}, chip, { fontFamily: 'monospace' }) }, item.id),
						]),
						react.createElement('div', {
							key: 'target',
							style: { fontSize: '11px', fontFamily: 'monospace', color: 'var(--dsw-alias-label-secondary)', wordBreak: 'break-all', marginBottom: '8px' },
						}, item.target || '（无目标文本）'),
						react.createElement('button', { key: 'ok', style: btn, disabled: busy || !state.passwordSet, onClick: function () { approve(item.id) } }, '批准并立即放行'),
						react.createElement('button', {
							key: 'no',
							style: Object.assign({}, btn, { marginLeft: '8px' }),
							disabled: busy,
							onClick: function () { ignore(item.id) },
						}, '忽略（拒绝）'),
					])
				})),
				react.createElement('input', {
					key: 'pw',
					type: 'password',
					autoFocus: true,
					placeholder: '批准密码',
					value: password,
					autoComplete: 'off',
					disabled: !state.passwordSet,
					onChange: function (e) { setPassword(e.target.value) },
					onKeyDown: function (e) {
						if (e.key === 'Enter' && pending.length > 0) approve(pending[0].id)
					},
					style: Object.assign({}, input, { width: '100%', marginTop: '2px' }),
				}),
				msg ? react.createElement('p', { key: 'm', style: msgStyle }, msg.text) : null,
			]))
		}

		/** 注册设置子页 + 极高风险批准弹窗。 */
		function apply(ctx) {
			ctx.slots.inject('settings.section', function () {
				return ctx.slots.register(
					{ name: 'settings.section', id: 'permission-matrix', order: 31, label: '权限矩阵' },
					Panel,
				)
			})
			// shell.overlay 是官方留给「浮在整个应用之上的自有表面」的 list 槽位
			// （默认点击穿透，只有卡片本身开启 pointerEvents）。
			ctx.slots.inject('shell.overlay', function () {
				return ctx.slots.register(
					{ name: 'shell.overlay', id: 'permission-matrix-password-approval', order: 60, label: '密码批准' },
					PasswordApprovalPrompt,
				)
			})
		}

		exports.apply = apply
		exports.inject = ['slots']
		return module.exports
	},
})
