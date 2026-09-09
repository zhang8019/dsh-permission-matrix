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

		/** 三档风险策略共用的选项（文案不绑定具体风险级别，避免串档）。 */
		var POLICY_OPTIONS = [
			{ value: 'allow', label: '放行' },
			{ value: 'deny', label: '拒绝' },
			{ value: 'ask', label: '转人工' },
		]

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
			var riskPolicies = effective.riskPolicies || {}
			var riskRow = function (levelKey, title, hint) {
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
					}, policyOptions),
					react.createElement('span', { key: 'h', style: desc }, hint),
				])
			}
			children.push(react.createElement('div', { key: 'risk', style: box }, [
				react.createElement('h2', { key: 'h', style: h2 }, '自动风险审批 · 三档策略'),
				react.createElement('p', { key: 'p', style: desc }, '低 / 中 / 高 三档风险各自可选「放行 / 拒绝 / 转人工」。极高风险（下面的硬拒绝清单）固定拒绝，人工也不能批准，不受任何策略影响。'),
				riskRow('low', '低风险策略', '允许规则命中、工作区内操作、裁判判定安全 → 默认放行'),
				riskRow('medium', '中风险策略', '规则未命中、裁判不确定 → 默认拒绝'),
				riskRow('high', '高风险策略', '裁判判定危险 → 默认拒绝'),
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

		/** 注册设置子页。 */
		function apply(ctx) {
			ctx.slots.inject('settings.section', function () {
				return ctx.slots.register(
					{ name: 'settings.section', id: 'permission-matrix', order: 31, label: '权限矩阵' },
					Panel,
				)
			})
		}

		exports.apply = apply
		exports.inject = ['slots']
		return module.exports
	},
})
