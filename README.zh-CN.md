# StarCouncil（星议 · 多智能体轻量协作与防假会套件）

**零第三方依赖（纯 Python 3.10+ 标准库）的多智能体指针黑板调度、防假开会哈希校验、六门禁空闲唤醒与可选分级把关工具。**

语言：[English](./README.md) | **简体中文** | [实战踩坑与修复实录（6 大核心经验）](./docs/PITFALLS_AND_FIXES.md)

---

## 为什么做 StarCouncil？（轻巧好用、不搞流程臃肿）

很多多智能体方案喜欢把几万字全文来回灌，或者搞“A 窗口审完 B 窗口审”的连环套娃审计，结果不仅烧额度还把对话拖成慢动作。**StarCouncil（1 个微内核 CLI + 3 个不到 120 行的薄 Skill）**只做省时间的事：

- **通吃四类环境（单机/多机 × 单订阅/多订阅）**：只有一个 Antigravity 订阅时，自动锁死单路串行三视角（避免触发 `429` 限流死锁）；多台电脑各自跑不同项目时**默认互不打扰、零日常交叉汇报**，只有聊到架构、Skill 构建或经验分享时才寄一张简短异步留言卡。
- **硬核防假开会校验（`meetings/<id>/`）**：严禁单一模型自己扮演四个角色“演假会”。必须有 `>= 2` 份来自不同参会方且 SHA-256 哈希独立的原始发言文件，才准出具 `MULTI_SEAT_DECISION` 决议；否则强制标为 `SOLO_SYNTHESIS` 或直接拦截。
- **两轮安灯拉闸（绝不带病放行）**：进外审前先跑本地单测修净同类问题；外部盲审最多 2 轮，第 2 轮仍有真问题立刻置为 `PITFALL_HALT` 停刷查根因，绝不修改测试或强行放水。
- **汇报强制说人话**：统一输出 `【结果】/【原因】/【需您操作】` 三行直白大白话。

## `.starcouncil/` 五类后台活档案

| 档案路径 | 职责与核心限制 |
| :--- | :--- |
| **`BOARD.md`** | 共享黑板，实时展现各席任务与当前持锁状态（严控 `< 3KB`） |
| **`logs/events.jsonl`** | 全自动追加的运行流水日志（记录每次 `init`、`dispatch`、`ack`、`lock`、`review`、`council`） |
| **`pitfalls.md` 与 `fixes_log.md`** | 踩坑错题本与修复日志（`log-pitfall` / `log-fix`，开会与把关时自动带出近期踩坑提醒） |
| **`meetings/<id>/`** | 多来源独立发言原件与哈希防伪校验（`council-submit` / `council-verify`） |
| **`inbox/<seat>.jsonl` + `artifacts/` + `locks/`** | `< 400B` 短指针信封、完整磁盘正文与 `fcntl.flock` 互斥锁 |

## 30 秒本地开箱体验

```bash
git clone https://github.com/Ziqi/starcouncil.git && cd starcouncil
python3 scripts/starcouncil.py init --root /tmp/sc-demo
python3 scripts/starcouncil.py doctor --root /tmp/sc-demo
python3 scripts/starcouncil.py council --root /tmp/sc-demo --topic "设计轻量多智能体协作工具"
python3 -m unittest discover -s tests -v
python3 scripts/starcouncil.py sanitize-lint --target .
```

## 三个模块化薄 Skill（均 `< 120` 行）

- [`skills/starcouncil-teamwork/SKILL.md`](./skills/starcouncil-teamwork/SKILL.md)：黑板指针协作、资源互斥锁与单跳跨机传信
- [`skills/starcouncil-review/SKILL.md`](./skills/starcouncil-review/SKILL.md)：可选 `0/1/2` 档把关、两轮安灯拉闸与大白话输出
- [`skills/starcouncil-council/SKILL.md`](./skills/starcouncil-council/SKILL.md)：按话题摇人、防假会多来源校验与单订阅防 `429` 模式
