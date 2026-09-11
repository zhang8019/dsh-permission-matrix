## v0.3.3 — 修正 `peerDependencies` 版本范围（修掉一个会挡住安装的缺陷）

`package.json` 里声明的官方包版本范围此前是 `^0.1.2-rc.1`，而 npm 上这两个包的**真实版本**是：

| 包 | npm 上的版本 |
|---|---|
| `@deepseek-ai/cordis` | `4.0.1-rc.1` · `4.0.1-rc.4` · `4.0.1` · **`4.0.2`** |
| `@deepseek-ai/schemastery` | `3.18.1-rc.1` · `3.18.1-rc.4` · `3.18.1` · **`3.18.2`** |

也就是说 `^0.1.2-rc.1` **匹配不到任何一个真实版本**：安装时会产生 peer 冲突（`ERESOLVE`），用户得自己加 `--legacy-peer-deps` 才能装上。

现在改为：

```json
"peerDependencies": {
  "@deepseek-ai/cordis": ">=4.0.1-rc.1",
  "@deepseek-ai/schemastery": ">=3.18.1-rc.1"
}
```

下界带**显式预发布标签**，所以 `4.0.1-rc.x`、`4.0.1`、`4.0.2`、`3.18.1-rc.x`、`3.18.1`、`3.18.2` 全部满足。这一点很关键：node-semver 只在范围内**存在与该版本同 `major.minor.patch` 元组、且自身带预发布标签的比较符**时才放行预发布版本，所以写成 `^4.0.0` 或 `>=0.0.0-0` 这类"看起来更宽"的范围反而会**静默排除**所有预发布构建。

同时把包描述里的 `three-tier risk policies` 更正为 `four-tier`（自 v0.3.0 起风险策略已是 低 / 中 / 高 / 极高 四档）。

**功能无变化**：测试 69 条全过，插件行为与 v0.3.2 一致。

---

**安装**

```sh
dsh plugin --profile <profile> add zhang8019/dsh-permission-matrix
```

或使用下方预构建 tarball。
