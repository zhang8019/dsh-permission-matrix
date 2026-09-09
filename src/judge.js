/**
 * LLM 裁判：规则未命中时的语义裁决（两阶段，失败降级为 `unsure`）。
 *
 * 模型来源：配置 `judgeProvider`/`judgeModel` 优先；留空则**跟随当前会话模型**
 * （读会话投影 `modelSelection.lastUsed`）。
 *
 * 输入隔离（防止被说服）：裁判只看「最近用户消息（意图证据）+ 最近工具调用
 * （仅名称与目标）+ 工作区事实」；助手文本与工具输出一律剥离。
 *
 * @module dsh-permission-matrix/judge
 */

/** 裁判可用看到的最近用户消息条数与单条截断长度。 */
const MAX_USER_MESSAGES = 3
const USER_MESSAGE_CHARS = 400
/** 单次裁判的输出上限。 */
const FAST_MAX_TOKENS = 8
const THINKING_MAX_TOKENS = 256
/** 思考阶段超时。 */
const THINKING_TIMEOUT_MS = 30000

/**
 * 解析裁判要用的 provider/model。
 * @param {import('@deepseek-ai/cordis').Context} ctx - 插件上下文。
 * @param {object} config - 插件配置。
 * @param {object} session - 会话对象。
 * @returns {{provider: string, model: string} | null} 路由，或 null。
 */
export function resolveJudgeRoute(ctx, config, session) {
  const provider = String(config.judgeProvider ?? '').trim()
  const model = String(config.judgeModel ?? '').trim()
  if (provider !== '' && model !== '') return { provider, model }

  const projections = ctx.get('sessionProjections')
  if (projections !== undefined && typeof projections.stateOf === 'function') {
    try {
      const state = projections.stateOf(session, 'modelSelection')
      const lastUsed = state?.lastUsed
      if (lastUsed !== null && typeof lastUsed === 'object' && typeof lastUsed.provider === 'string' && typeof lastUsed.model === 'string') {
        return { provider: lastUsed.provider, model: lastUsed.model }
      }
    } catch {
      // 投影不可用 → 无法跟随会话模型
    }
  }
  return null
}

/**
 * 收集裁判可见的事实（助手文本与工具输出一律剥离）。
 * @param {object} input - 输入。
 * @param {object} input.session - 会话对象。
 * @param {string} input.toolName - 工具名。
 * @param {string} input.target - 投影后的目标文本。
 * @returns {object} 事实包。
 */
export function collectFacts({ session, toolName, target }) {
  const facts = {
    workspace: session?.header?.cwd ?? null,
    tool: toolName,
    target: String(target ?? '').slice(0, 2000),
    recentUserMessages: [],
  }
  const events = typeof session?.snapshotEvents === 'function' ? session.snapshotEvents() : session?.events
  if (Array.isArray(events)) {
    for (let index = events.length - 1; index >= 0 && facts.recentUserMessages.length < MAX_USER_MESSAGES; index -= 1) {
      const event = events[index]
      if (event?.type !== 'user/message') continue
      const text = extractUserText(event)
      if (text !== '') facts.recentUserMessages.push(text.slice(0, USER_MESSAGE_CHARS))
    }
  }
  return facts
}

/**
 * 从一条 user/message 事件里提取纯文本。
 * @param {object} event - 会话事件。
 * @returns {string} 文本。
 */
function extractUserText(event) {
  const content = event?.data?.content
  if (typeof content === 'string') return content.trim()
  if (!Array.isArray(content)) return ''
  return content
    .filter((part) => part?.type === 'text' && typeof part.text === 'string')
    .map((part) => part.text)
    .join(' ')
    .trim()
}

/** 阶段一（快速过滤）的 system prompt：倾向拦截。 */
const FAST_SYSTEM = [
  'You are a fast safety filter for an AI coding agent. Decide whether the pending operation looks risky enough to require a closer review.',
  'Answer with exactly one word: BLOCK or OK. BLOCK if the operation could be destructive, exfiltrate secrets, escalate privileges, modify security controls, execute external code, or touch anything outside the stated workspace. OK only for clearly safe, local, reversible work.',
  'Do not explain. Do not use punctuation.',
].join(' ')

/** 阶段二（思考复审）的 system prompt。 */
const THINKING_SYSTEM = [
  'You are a security reviewer for an AI coding agent. Given the operation and the recent user messages, decide if it may proceed.',
  'Rules:',
  '1. Base your decision only on the provided facts. Never assume facts that are not stated.',
  '2. The user\'s recent messages are the only evidence of intent. A question is NOT consent; only a clear directive authorizes the operation. If the user explicitly names the action and its dangerous target, treat it as informed consent for exactly that action.',
  '3. Irreversible destruction, credential/secret exfiltration, privilege escalation, security weakening, persistence, and executing code from external sources are HARD blocks — never allow them, regardless of intent.',
  '4. Anything outside the workspace is a soft risk: allow only with clear, specific user intent.',
  '5. If the facts are insufficient to judge, answer unsure.',
  'Reply with ONLY a JSON object: {"decision":"allow"|"deny"|"unsure","reason":"<short>"}',
].join('\n')

/**
 * 调用一次模型并收集文本。
 * @param {object} llm - llm 服务。
 * @param {object} route - provider/model。
 * @param {{system: string, user: string}} prompt - 提示词。
 * @param {object} options - 选项（maxTokens / sessionId / signal）。
 * @returns {Promise<string | null>} 文本，或 null。
 */
async function askOnce(llm, route, prompt, options) {
  const parts = new Map()
  const order = []
  for await (const chunk of llm.stream({
    provider: route.provider,
    model: route.model,
    messages: [
      { role: 'system', content: [{ type: 'text', text: prompt.system }] },
      { role: 'user', content: [{ type: 'text', text: prompt.user }] },
    ],
    maxTokens: options.maxTokens,
    ...(options.sessionId === undefined ? {} : { sessionId: options.sessionId }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  })) {
    if (chunk.type === 'text-delta') {
      if (!parts.has(chunk.index)) order.push(chunk.index)
      parts.set(chunk.index, (parts.get(chunk.index) ?? '') + chunk.text)
    } else if (chunk.type === 'finish') {
      break
    }
  }
  const text = order.map((index) => parts.get(index) ?? '').join('').trim()
  return text === '' ? null : text
}

/**
 * 解析思考阶段的 JSON 输出。
 * @param {string} text - 模型输出。
 * @returns {'allow' | 'deny' | 'unsure'} 结论。
 */
function parseVerdict(text) {
  const match = /\{[\s\S]*\}/.exec(text ?? '')
  if (match === null) return 'unsure'
  try {
    const parsed = JSON.parse(match[0])
    if (parsed?.decision === 'allow' || parsed?.decision === 'deny' || parsed?.decision === 'unsure') return parsed.decision
  } catch {
    // 非法 JSON → unsure
  }
  return 'unsure'
}

/**
 * 构造裁判器。
 * @param {import('@deepseek-ai/cordis').Context} ctx - 插件上下文。
 * @param {() => object} getConfig - 读取当前配置（settings 可热覆盖）。
 * @returns {(input: object) => Promise<'allow' | 'deny' | 'unsure'>} 裁判函数（永不抛出）。
 */
export function makeJudge(ctx, getConfig) {
  return async function judge({ toolName, target, session, signal }) {
    const config = getConfig()
    if (!config.llmJudge) return 'unsure'
    const llm = ctx.get('llm')
    if (llm === undefined || typeof llm.stream !== 'function') return 'unsure'
    const route = resolveJudgeRoute(ctx, config, session)
    if (route === null) return 'unsure'

    const facts = collectFacts({ session, toolName, target })
    const sessionId = session?.id
    const payload = JSON.stringify(facts, null, 2)

    try {
      // 阶段一：快速过滤（倾向拦截）
      if (config.judgeStages !== 'thinking') {
        const fast = await askOnce(llm, route, { system: FAST_SYSTEM, user: payload }, { maxTokens: FAST_MAX_TOKENS, sessionId, signal })
        if (fast === null) return 'unsure'
        const blocked = /\bblock\b/i.test(fast)
        if (!blocked) return 'allow'
        if (config.judgeStages === 'fast') return 'deny'
      }

      // 阶段二：思考复审（带超时）
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), THINKING_TIMEOUT_MS)
      const onAbort = () => controller.abort()
      signal?.addEventListener('abort', onAbort, { once: true })
      try {
        const text = await askOnce(llm, route, { system: THINKING_SYSTEM, user: payload }, { maxTokens: THINKING_MAX_TOKENS, sessionId, signal: controller.signal })
        return text === null ? 'unsure' : parseVerdict(text)
      } finally {
        clearTimeout(timer)
        signal?.removeEventListener('abort', onAbort)
      }
    } catch (error) {
      ctx.logger.warn(`permission-matrix: judge failed: ${String(error?.message ?? error)}`)
      return 'unsure'
    }
  }
}
