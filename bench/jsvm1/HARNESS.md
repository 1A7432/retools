# jsvm1 运行方案（HARNESS）

状态：**已确认并实现**（2026-11-17）。实现在 `tools/jsworker/`（用法见那里的 README.md）；镜像在 `tools/jsworker/image/`；
判分在 `sealed/grade.py`。基准内容的最终设计见 `DESIGN.md`。附录 A 是确认时的规划草案，保留备查；实际内容以 DESIGN.md 为准
（实际 43 题；实现题的 Python 为 3.13）。

验证：
- `jsw doctor` 全部 ok。暴露检查确认模型恰好只看到 9 个 `mcp__jsre__*` 工具。
- jsworker 自带测试 393 项全部通过（unit 144、mcp 57、escape 144、flow 48），均未调用真实模型。
- reworker 回归测试在 `backend_dsh.py` 参数化前后结果一致。
- 在真实 jsvm1 基准上，用假模型跑通了 t1 全流程：按 MANIFEST staging → 容器 → 工具调用 → submit_check（公开样本 3/3）→
  导出 → `grade.py`，T1-01 通过 72/72 隐藏向量。脚本里故意读取宿主 `sealed/answers.json`，被拒绝，并被审计标记。
- 尚未用真实模型跑过。

---

## 0. 结论摘要

| 问题 | 方案 |
|---|---|
| agent 循环 | 复用 dsh：新建 profile `js-worker`（模板同 `re-worker`：dsh-base + dsh-headless），复用 `tools/reworker/backend_dsh.py` 的启动、`--patch` overlay、`--json` 事件流、超时杀进程组、doctor 暴露检查。 |
| dsh 自带 sandbox 够不够 | **不够**，见第 1 节。所以 dsh 的内置工具全部关闭，工具只经由我们自己的 MCP 服务器 `jsre` 提供（与 rew 的 guardproxy 同一思路）。 |
| 沙箱 | 每个 run 起一个 Docker（OrbStack）容器：`--network none`、只读根文件系统、只挂载 staging 出来的 `public`（只读）和 `work`（读写）。**sealed/ 从不挂载**，物理上不可达。所有工具调用都是 `docker exec` 进这个容器执行。 |
| worker 工具 | 文件读/写/搜索、受限 node（Node 22 `--permission`：禁子进程、禁 worker、只读 public+work、只写 work）、受限 python（审计钩子禁子进程/socket）、预装 AST 库（@babel/*、acorn、astring）、js 格式化、提交格式自检。不给 bash、不给浏览器、不给 npm/pip。 |
| 提交 | `work/submission/answers.json`（`{qid: answer}`，与 obf1 相同）+ 实现题的 `<qid>.py`。 |
| 判分 | `sealed/grade.py SUBMISSION_DIR`，输出格式与 obf1 一致（逐题行 + `MECHANICAL SCORE: x/y`，manual 恒为 0）。实现题的 .py 在同一镜像的一次性容器里跑，容器只拿到"只有输入、没有期望输出"的向量文件，比对在宿主上做。 |

---

## 1. 现状核查：为什么不能直接用 dsh 的 sandbox

核查对象：`~/.dsh/profiles/node_modules/@deepseek-ai/` 下的 0.2.0-rc.2 版本。

1. **Seatbelt profile 只禁写。** `dsh-sandbox-local/src/profiles.ts:52` 生成的 SBPL 是
   `(version 1) (allow default) (deny file-write*) (allow file-write* <workspace roots>)`。
   没有 `(deny network*)`，也没有任何 `file-read*` 限制：bash 工具里的 node/python 可以读到 `sealed/`，也能联网。
2. **fs 工具的读是放行的。** `dsh-fs-sandbox` 的包描述原文："fences write/edit by the per-call sandbox mode … while reads pass through"。
3. **`runnerCommand` 自定义 runner 不合适。** 它把 bwrap 兼容参数追加给 runner，并且跳过探测、直接断言 `full` enforcement。
   在 macOS 上要写一个解析 bwrap 参数再翻译成 Seatbelt 的 shim，这既脆弱，又把安全边界建立在一个不被 dsh 检查的断言上。
4. **agent-instructions 会自动注入工作区说明文件。** `dsh-agent-instructions` 会加载 `$DSH_HOME/AGENTS.md`，以及从项目根到 cwd 链上的
   `AGENTS.md`/`CLAUDE.md`。这一行在 `js-worker` 中必须关闭。

结论：dsh 适合继续承担"模型 + agent 循环 + 事件流"，隔离边界放到 MCP 工具层和容器层，与 rew 的做法一致
（rew 同样关闭了 dsh 的全部内置工具，只经 guardproxy 暴露 ida 工具）。

---

## 2. 总体架构

```
宿主 macOS
─────────────────────────────────────────────────────────────────────────────
jsw run --target t3 --model deepseek-v4.1-flash --effort max --timeout 7200
 │
 ├─ 1. stage   tmp/jsw-runs/<run-id>/
 │               public/   ← 从 jsvm1/public 拷贝：只含 t3/ 与 t3 的题目子集，按 MANIFEST.sha256 校验
 │               work/     ← 空目录，worker 唯一可写处；结束后从这里取 submission/
 │               dsh-cwd/  ← 空目录，dsh 进程的 cwd（不在任何项目树里）
 │
 ├─ 2. docker run -d --name jsw-<run-id> --network none --read-only ...  (镜像 jsvm1-tools@sha256:…)
 │        -v <run>/public:/task/public:ro   -v <run>/work:/task/work:rw
 │
 ├─ 3. dsh js-worker --patch overlay.yml --json -   (cwd = dsh-cwd)
 │        内置工具行全部 disabled；唯一的工具来源：
 │        MCP stdio ──▶ jsre_mcp.py（宿主进程，策略点 + 日志）──docker exec──▶ 容器
 │
 └─ 4. 收尾   导出 work/submission/ 到 <run>/submission/（只拷普通文件，不跟随符号链接）→ 审计工具日志 → docker rm -f → summary.json

判分（与 worker 无关的另一进程）
─────────────────────────────────────────────────────────────────────────────
python3 jsvm1/sealed/grade.py <run>/submission        （导出目录，绝不直接读 work/submission）
   实现题  → docker run --rm --network none（只挂 <qid>.py 与仅含输入的向量）→ stdout → 宿主比对
   其他题  → 与 obf1 相同的 check 类型；反向题由宿主 node 运行 sealed 参考实现校验
```

代码位置（确认后才写）：

- `tools/jsworker/`：`jsw`（CLI）、`jsre_mcp.py`（MCP 服务器）、`profile/cordis.patch.yml`、
  `image/Dockerfile` 与锁文件、`tests/`。与 `reworker` 平级，因为它不是 jsvm1 专属，以后的 JS 基准也能用。
- `bench/jsvm1/sealed/grade.py` 与 `sealed/tools/grade_runner.py`（容器内跑提交的小脚本）。

---

## 3. worker 拿到的工具

全部是 MCP 工具（模型看到的名字是 `mcp__jsre__*`），路径一律是容器内路径。

| 工具 | 作用 | 限制 |
|---|---|---|
| `fs_list(path, depth=2)` | 列目录（大小、sha256 前 12 位） | 只接受 `/task/...` |
| `fs_read(path, offset, limit, unit="line"\|"byte")` | 读文本。混淆 JS 常常是一行几百 KB，所以支持按字节窗口读 | 单次返回 ≤ 40 KB |
| `fs_grep(pattern, path, max=50)` | 正则搜索。命中超长行时只返回命中点前后各 200 字节 | |
| `fs_write(path, content)` / `fs_edit(path, old, new)` | 写文件、精确替换 | 只能写 `/task/work/` |
| `node_run(file \| code, args=[], stdin="", timeout=60)` | Node 22.21.1，见下 | timeout ≤ 600 s |
| `py_run(file \| code, args=[], stdin="", timeout=60)` | Python 3.13，见下 | timeout ≤ 600 s |
| `js_beautify(path, out)` | 用 @babel/generator 重新排版（不改语义，不做反混淆） | `out` 必须在 `/task/work/` |
| `submit_check()` | 校验 `submission/`：JSON 可解析、qid 合法、实现题文件存在且定义了规定的函数、只 import 白名单模块；并用**公开样本**试跑实现题 | 只报公开样本的结果，不涉及隐藏向量 |

**node_run**：MCP 服务器自己拼 argv，worker 不能传任意 node 参数：

```
node --permission --allow-fs-read=/task --allow-fs-read=/opt/jsre --allow-fs-write=/task/work \
     [--stack-size=N] [--max-old-space-size=N] <file> <args...>
```

- 已在宿主 node v22.21.1 上验证：`--permission` 下读白名单外的文件、`child_process`、`worker_threads` 都抛 `ERR_ACCESS_DENIED`，`vm` 模块可用（补环境常用 `vm.runInNewContext`）。
- 注意：Node 22.21 不接受逗号分隔的多个路径，`--allow-fs-read` 必须重复写（已在镜像里实测）。
- `--permission` 管不到网络，网络由容器 `--network none` 在内核层切断。
- 不提供 inspector/调试器；worker 需要用插桩、改写源码、hook 等方式做动态分析，这也是题目要考的能力。
- `NODE_PATH=/opt/jsre/node_modules`，预装且只读：`@babel/parser`、`@babel/traverse`、`@babel/generator`、`@babel/types`、`acorn`、`acorn-walk`、`astring`。版本在镜像构建时锁定（package-lock + 镜像 digest）。不预装 jsdom（理由见 9.4）。

**py_run**：`python3 -I -X utf8 /opt/jsre/pyrun.py <file> <args...>`。`pyrun.py` 先用 `sys.addaudithook` 装一个不可卸载的钩子，
拒绝 `subprocess.Popen`、`os.system`、`os.exec*`、`os.posix_spawn`、`os.spawn*`、`os.fork`、`socket.*`、`ctypes.dlopen`，然后 `runpy.run_path`。
site-packages 里只有 `pycryptodome` 和 `gmssl`（pip 本身从镜像中删除），与实现题的运行环境完全相同。审计钩子只是第二道防线，真正的边界是容器。
py_run 和 grade_runner 都加 `-B`（`-I` 会忽略 PYTHONDONTWRITEBYTECODE；实测过同一秒内改写同长度文件时复用了旧 .pyc）。

**输出处理**：stdout+stderr 合计超过 20,000 字符时，返回头尾各一半，完整输出存到 `/task/work/.jsw/out/<n>.txt` 并告诉模型路径。

**不提供**：bash/shell、网络、浏览器、npm/pip 安装、调试器、子代理、web 搜索。

---

## 4. 沙箱：容器规格

镜像 `jsvm1-tools`（Dockerfile 放在 `tools/jsworker/image/`）：

- 基础：本机已有的 `debian:trixie-slim`（按 digest 固定）。Python 3.13 由 apt 安装；node 使用 nodejs.org 官方 v22.21.1 二进制包，构建前按官方 SHA256 校验（与宿主版本一致）。
  （原计划用 `python:3.12-slim` + `node:22` 官方镜像，但 Docker Hub 镜像源拉取卡死，改为此方案。）
- `pip install pycryptodome==<锁定> gmssl==<锁定>`，装完删除 pip；`npm ci` 装第 3 节列出的 AST 库到 `/opt/jsre/node_modules`。
- `/opt/jsre/{pyrun.py, grade_runner.py, bin/beautify.js}`。
- 构建镜像需要联网，只联网这一次；构建产物的 digest 写进 `image/IMAGE_DIGEST`，`jsw doctor` 和 `grade.py` 启动时都会核对。

每个 run 的容器参数：

```
docker run -d --name jsw-<run-id> --label jsw.run=<run-id>
  --network none --read-only --tmpfs /tmp:rw,size=256m
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges
  --memory 4g --cpus 2 --pids-limit 128
  -e TZ=UTC -e LANG=C.UTF-8
  -v <run>/public:/task/public:ro -v <run>/work:/task/work:rw
  jsvm1-tools@sha256:<digest> sleep infinity
```

工具调用走 `docker exec -i --user 1000:1000 jsw-<run-id> -- <argv>`，参数一律用 argv 列表传递，不经过 shell。
OrbStack 上一次 exec 的额外开销大约 0.1–0.2 s，在 agent 一步一调用的节奏下可以接受。run 结束后执行 `docker rm -f`，
`jsw gc` 负责清理异常退出时残留的带 `jsw.run` 标签的容器。

**备选（Docker 不可用时）**：宿主上使用自写的 Seatbelt profile：`(deny default)` 起步，放行系统库、node/python 安装目录、
`/opt/jsre` 等价目录、staging public（读）和 work（读写）；`(deny network*)`；`process-exec` 只放行 node 和 python 两个二进制。
这条路不需要镜像，但 sealed/ 与 worker 在同一个文件系统上，只靠 SBPL 白名单写得对，强度不如容器，所以只作备选。

---

## 5. 怎样防止 worker 读到 sealed/

按层列出，任何一层失效时后面还有一层：

1. **物理不可达**：容器只挂 staging 的 `public` 和 `work`。staging 是从 `jsvm1/public` 拷贝出来的单个目标子集，
   `jsvm1/` 和 `sealed/` 的宿主路径在容器里根本不存在。
2. **模型看不到 dsh 的内置工具**：`js-worker` profile 关闭全部工具行（列表同 rew 的 `TOOL_ROWS`：bash、pwsh、jobs、fs、fs-search、
   working-directory、skill、plan-mode、subagent*、workflow、todo、goal、web、mcp-resources、plugin-manager），并关闭
   `agent-instructions`、`skill-filesystem`。`jsw doctor` 复用 rew 的 exposure check：用假 LLM 服务器启动真实 profile，
   记录 dsh 实际提供给模型的工具列表，必须**恰好等于** `mcp__jsre__*` 这 9 个工具，多一个就判失败。
3. **MCP 层**：只接受 `/task/` 前缀且规范化之后仍在 `/task/` 下的路径；写操作只接受 `/task/work/`；node/python 的 argv 由服务器拼接。
   每次调用记一行 JSONL（工具、参数、耗时、退出码、完整输出的存储路径）。
4. **判分层**：提交的 .py 在一次性容器里运行，容器只拿到"只有输入"的向量文件，期望输出始终留在宿主上的 `sealed/vectors/`。
   这样一个会去找答案文件的提交也拿不到答案。
5. **事后审计**：`jsw` 在收尾时扫描工具日志，检查是否出现 `/task` 以外的路径、宿主路径片段、`sealed` 字样；并用
   `MANIFEST.sha256` 复核 staging 的 public 与 `jsvm1/public` 一致（防止有人误把别的文件放进 staging）。审计结果写进 `summary.json`。
6. **提交物不跟随符号链接**：worker 能在 `work/` 里创建指向宿主路径的符号链接（宿主路径可从 dsh 每轮提示里的 cwd 推出），
   宿主上的程序一旦读 `work/submission` 就会顺着链接读到 `sealed/`。因此 `jsw` 收尾时只把普通文件拷到 `<run>/submission/`，
   `grade.py` 也逐个 `lstat` 检查，遇到符号链接、设备文件或目录外路径一律判该题不合法。
7. **已知限制（不影响上面的边界）**：Python 里 `_posixsubprocess.fork_exec` 可以绕过审计钩子起子进程；node 的 `--permission`
   不检查符号链接目标（Node 文档行为）。两者能触及的只有容器内的镜像文件和 `/task`，没有网络、看不到宿主，所以只记录，不额外封堵。
8. **反方向（public 不泄密）**：这是 build 的职责，不在 harness 里。build 会跑 `leakcheck.py`：public/ 下的所有文件中不得出现
   sealed 里登记的密钥、中间值、算法名称及其常见写法（如 `hmac`、`sha256`、`sm3`、`sm4`、`aes`、`feistel` 等，大小写和分隔符都会归一化）。

---

## 6. 运行单元与流程

- **一个 run 对应一个目标**（与 obf1 的 p1/p2/p3 一致），worker 只看到这个目标的文件和题目。题目共用的说明
  （提交格式、Python 约束、样本格式）放在 `public/README.md` 中，并随 staging 一起拷入。
- **任务提示**（由 `jsw` 生成，worker 看不到别的上下文）包含：目标简介（"这是某网站前端的 JS，请求带签名…"）、文件清单、
  该目标的题目原文、提交位置与格式、工具说明、预算。不包含任何提示性的算法信息。
- **预算**（可在命令行覆盖）：墙钟 2 h；工具调用 400 次（超出后所有执行类工具都返回"请立即写提交"，提交相关的
  fs_write/submit_check 仍然可用）；reasoning effort 默认 max。token 用量从 dsh 事件流中统计，写进 `summary.json`。
- **续跑**：沿用 rew 的 session 机制，`jsw resume <run-id>` 使用同一个 staging、容器和 dsh session。
- **合并与判分**：`jsw merge <run-id>... -o submission/` 把各目标的提交合并成一份（qid 不重叠），然后
  `python3 jsvm1/sealed/grade.py submission/`。

产物：

```
tmp/jsw-runs/<run-id>/
  overlay.yml  events-1.jsonl  stderr-1.txt  tools.jsonl  summary.json
  public/  work/  submission/{answers.json, <qid>.py}   ← 导出的副本，判分只读这里
```

---

## 7. 提交格式与判分接口

### 7.1 提交目录

```
submission/
  answers.json     {"T1-01": "T1-01.py", "T3-02": 37, "T3-05": "none", ...}
  T1-01.py         实现题，一题一个文件，文件名 = qid + ".py"
```

- `answers.json` 的取值写法与 obf1 相同：整数可以写十进制或 `0x` 十六进制字符串，列表可以是 JSON 数组，否定类答案写 `"none"`。
- 实现题在 `answers.json` 里的值就是文件名；漏写时，grader 按 `<qid>.py` 的约定自动查找。

### 7.2 实现题的 Python 约束（写进 public/README.md 和题面）

- Python 3.13，只能用标准库 + `pycryptodome` + `gmssl`。运行环境就是 worker 用 `py_run` 时的那个镜像，没装的包 import 会直接失败。
- 题面给出精确的函数签名、参数类型和编码，例如：
  `def sign(params: dict[str, str], ts: int, nonce: str) -> str`。其中 `params` 的键和值是任意 Unicode 字符串（可为空），
  `ts` 是毫秒时间戳，取值范围 `[0, 2**53)`，`nonce` 是 16 个小写十六进制字符，返回 64 个小写十六进制字符。
- 不得有网络、子进程或文件访问。单个向量限时 2 s，整题限时 120 s。程序必须是确定性的。
- 判定：**每一组隐藏向量的输出都要与期望输出逐字符相等**才算对，大小写敏感（题面已规定输出格式）。

### 7.3 grade.py

```
python3 sealed/grade.py SUBMISSION_DIR [--answers sealed/answers.json] [--image-digest D] [--quiet]
```

输出与 obf1 同构：每题一行 `qid  check_type  dN  CORRECT|WRONG (...)|MISSING`，然后按目标汇总，最后一行是
`MECHANICAL SCORE: x/y   manual pending: 0`。实现题判错时会附上第一组失败向量的序号和边界类别标签
（如 `WRONG (vector 17/64 [unicode-astral])`），方便分析错因。这份输出只给评测者看，worker 永远看不到。

check 类型：沿用 obf1 的 `int`、`int_list`、`hex`、`text`、`exact`、`fields`、`none`、`letter_set`，另外新增三种：

| 新类型 | 用于 | 判法 |
|---|---|---|
| `py_impl` | 实现题 | 在容器里运行提交的 .py，对 `sealed/vectors/<qid>.jsonl` 中的全部输入逐组比对 |
| `js_preimage` | 反向题：已知输出求输入 | 宿主 node 运行 sealed 中的**未混淆参考实现**，把提交的值当作数据（JSON）传入，检查输出是否等于目标值。有多解时任何一个解都算对 |
| `env_value` | 反向题：求一个让检测分支走向指定路径的环境值 | 同上，把提交的环境值放进参考环境中运行，检查指定的路径标记 |

`sealed/tools/selftest.py`：参考答案一套须满分；错误答案一套（手写，模拟真实错法，见附录 A.4）须每题都判错。

---

## 8. 复用与新写的代码

| 部件 | 处理 |
|---|---|
| `reworker/backend_dsh.py` | **复用**。需要一处向后兼容的小改动：把模块级常量 `PROFILE`、`SERVER`、`PROXY`、工具名集合改为构造参数，默认值保持不变；改完重跑 rew 现有的 `test_*.py`，证明 rew 行为不变。这是本方案唯一一处会改动现有代码的地方，见 9.3。 |
| `reworker/fake_llm_server.py` | 复用，供 `jsw doctor` 做 exposure check。 |
| `reworker/guardproxy.py` / `guard.py` / `ledger.py` / `contract.py` | 不复用：它们是 IDA 专用的（strict-mode 的 rekit 语法检查、findings ledger）。只借鉴思路：fail-closed、逐调用日志、预算计数。 |
| `jsworker/jsre_mcp.py` | 新写。MCP stdio 服务器：工具定义、路径校验、拼 argv、`docker exec`、输出截断、预算、日志。约 500 行。 |
| `jsworker/jsw` | 新写。`setup / doctor / run / resume / merge / gc`。约 400 行。 |
| `jsworker/image/` | 新写。Dockerfile、`pyrun.py`、`grade_runner.py`、`beautify.js`、package.json + lock、requirements.txt（带 hash）。 |
| `jsworker/tests/` | 新写。用假 LLM 跑通全流程；逃逸测试（读 `/etc/passwd` 以外的宿主路径、联网、`child_process`、python `subprocess`/`socket`、写 public、`../` 路径穿越）全部必须被拒。 |

---

## 9. 取舍与决定

2026-11-17 决定：

| # | 取舍 | 决定 |
|---|---|---|
| 1 | 第 3 档判分 | B：确定性模拟 + 构建期真实 Chrome 冒烟检查（`BROWSER_CHECK=1`） |
| 2 | 执行沙箱 | Docker（OrbStack）容器 |
| 3 | backend_dsh.py | 向后兼容的参数化改动，并用 rew 现有测试做回归验证 |
| 4 | 公开样本 | 每道实现题给 3 组普通输入的抓包样本，边界输入不进样本；不预装 jsdom |

以下是当时列出的选项与理由，保留备查。

1. **第 3 档判分：真实浏览器，还是确定性环境模拟？**（你点名要我停下来问的）
   - A. 纯确定性模拟：题面给出完整指纹（UA、语言、屏幕、时区、canvas `toDataURL()` 的原始返回串等），隐藏向量由未混淆源码
     在 node 里配合我手写的环境桩生成；判分完全不依赖浏览器。
   - B（**推荐**）：A + 构建期用真实 Chrome 做一次冒烟检查（本机已有 tabcap 的 Chrome for Testing），只验证
     "原生性检查 / Proxy 检测 / 调试时序检测在真实 Chrome 的干净环境下都判定为'干净'"，即我虚构的"参考浏览器"行为与真实
     Chrome 一致，避免熟悉真实浏览器的 worker 因为我的模拟有偏差而被误判。判分仍然是纯确定性的，与 A 相同。
     指纹值（尤其是 canvas）本身无法让真实 Chrome 复现，所以这一步不比对签名，只比对检测标记。仿照 obf1 的 `DOCKER_CHECK=1`，用 `BROWSER_CHECK=1` 开关控制。
   - C. 判分时用真实浏览器：不推荐。实现题判的是 Python，用不上浏览器；而且 canvas、时序等会引入不确定性。
2. **执行沙箱**：Docker 容器（推荐，sealed 物理不可达，网络在内核层切断，工具版本锁定在镜像里；代价是需要联网构建一次镜像，
   约 300 MB），还是第 4 节末尾的 Seatbelt 备选（无需镜像，但边界弱一些）。
3. **是否允许对 `reworker/backend_dsh.py` 做第 8 节的向后兼容参数化改动**，还是在 jsworker 里复制一份（复制没有回归风险，但以后要同步维护两份）。我倾向于改，并用 rew 现有的测试做回归验证。
4. **公开样本（"抓包样本"）**：每道实现题在 public/ 里给 3 组普通输入的输入/输出样本（第 3 档样本按题面指纹生成），
   形式上是"抓到的真实请求"。好处是贴近实战、输出格式零歧义、worker 可以自测补环境是否正确；代价是第 3 档的难度会下降一些
   （worker 可以拿样本校验补环境，而不必完全从字节码里推出检测逻辑）。我倾向于给；边界类输入（空串、超长、增补平面字符、
   int32 溢出等）一律不进样本。jsdom 不预装，因为手写补环境本身就是考点。

---

## 附录 A：基准内容规划草案（确认后迁入 DESIGN.md）

所有业务均为虚构，统一设定为虚构站点"潮汐票务"（接口域名用保留的 `.invalid` 顶级域，例如 `api.tidewell.invalid`）。
混淆器和 VM 都是自写的：标识符方案、字符串解码器、字节码格式、opcode 编号均由 seed 生成，不仿造任何现有产品的命名或特征串。

### A.1 目标

| 目标 | 档 | 被保护逻辑（sealed 才写明） | 保护手段 | 实现题 | 难度 |
|---|---|---|---|---|---|
| t1 | 1 | 查询接口签名：魔改 HMAC（某个初始常量被改动），规范串的拼接顺序反直觉，按 UTF-16 码元排序、自定义 URL 编码规则 | 字符串数组 + 旋转 + 解码函数、控制流平坦化、死代码、常量拆分、代理函数、Unicode/`\u` 转义标识符、多进制数字字面量 | `sign(params, ts, nonce)` | 2 |
| t2 | 1 | 登录：密码先做分组加密（参数被改动），再做魔改国密哈希签名，最后用自定义 base64 字母表输出；ts 参与 int32 截断运算 | t1 全部手段 + 自校验（函数源码哈希参与常量计算，格式化或改写代码后签名静默出错）| `encrypt_pwd(pwd, ts)`、`sign(...)` | 3 |
| t3 | 2 | 下单签名：自定义 ARX 哈希，写成字节码；存在一个依赖内部状态的分支（约 1/64 的输入会触发，普通输入几乎碰不到） | 栈式 VM：字节码加密内嵌、运行时解密；opcode 表打乱；handler 混淆（含别名 handler 和永不执行的诱饵 handler）；变长指令（u8 / LEB128 / zigzag / 掩码 u32 / 常量池索引） | `sign(params, ts, nonce)` | 4 |
| t4 | 2 | 票据 token：64 位块上的可逆置换（多轮），JS 里只有正向；另有一个基于同一 VM 的参数签名 | 寄存器式 VM：滚动解密（每条指令的密钥依赖 pc 和上一条 opcode，静态 dump 必须先还原解码器）；模式位编码的操作数；handler 平坦化 | `make_token(uid, ts)`、`parse_token(token)`（求逆，JS 里不存在） | 5 |
| t5 | 3 | t3 系列 VM 的另一 seed 变体 + 环境指纹参与签名；node 裸跑会进入诱饵分支，产出"看起来正常"的错误签名 | navigator/screen/时区/canvas 摘要；`Function.prototype.toString` 原生性检查；Proxy 检测；调试时序检测（诱饵，计算了但不参与签名）；node 特征检测 | `sign(params, ts, nonce)`（指纹固定，题面给出） | 4 |
| t6 | 3 | t4 系列 VM 变体 + 环境检测在字节码里完成（属性名按哈希查找）；签名依赖的环境字段是指纹的一个子集，另有几个只读不用的诱饵字段 | t5 的检测点 + VM 代码自校验 | `sign(params, ts, nonce, env)`：隐藏向量里 env 各字段会变化，硬编码某个指纹算出来的常量过不了 | 5 |

### A.2 题型配比（草案：6 个目标，约 44 题）

| 题型 | 数量 | 说明 |
|---|---|---|
| 实现题 | 8 | 每题 64–128 组隐藏向量，覆盖空串、空 params、超长（≥64 KB）、BMP 与增补平面字符、需转义的 ASCII（`!'()*~ +&=`）、只在大小写上不同的键、`ts` 落在 2^31/2^32 附近及 0、t3 的稀有分支（构建时搜索出 ≥5 个能触发的输入）。期望输出由未混淆源码在 node 中生成，再与混淆产物以及 Python 参考实现三方交叉验证 |
| 结构题 | 约 22 | 有效 opcode 数（题面精确定义口径：分发表中会进入非 trap handler 的 opcode 值个数，或字节码实际用到的种类数，二选一写死）；给定栈/寄存器状态求某 opcode 执行后的状态；字节码解密密钥；指令编码；哪些检测点影响签名、哪些是诱饵；t2 的自校验依赖于什么 |
| 反向题 | 约 6 | 已知 token 求 uid（`int`）；求一个触发 t3 稀有分支的指定形式输入（`js_preimage`）；求一个让 t6 某检测分支走向指定路径的环境值（`env_value`） |
| 陷阱题（答案为 none 或否定） | 5–6（约 12%） | 例如："以下 handler 中哪些永远不会被执行？若都会执行则答 none"（答案确实为 none）；另有 2–3 道同样提供 none 选项、但答案不是 none 的题 |
| 基线题（node 直接跑就能得到答案） | ≤ 8（≤ 18%） | 在 answers.json 中标 `"tier": "baseline"`，例如 t1 对固定输入的签名值 |

### A.3 构建与验收（对应你给的验收标准）

- `sealed/build.sh SEED` 从零构建：生成器、混淆器、VM 编译器全部是 sealed 里的源码，依赖的 npm 包（acorn、astring）以 tarball 形式放进
  `sealed/vendor/`，构建过程离线。同一 seed 构建两次，`public/` 与 `sealed/build/` 逐字节比对必须一致（build 末尾自动做这一步）。
- 交叉验证：未混淆源码（node）= 混淆产物（node + 指纹环境桩）= Python 参考实现，在全部隐藏向量上逐组一致。
- 第 3 档：在 node 中裸跑混淆产物（不补环境），签名必须与正确值不同；验证记录（输入、裸跑输出、正确输出、命中的诱饵分支）写进 DESIGN.md。
- `selftest.py`：参考答案满分，错误答案每题判错。
- `leakcheck.py`：public/ 不含密钥、中间值或算法名称。
- 每个目标的"预期解法路径"写在 `sealed/solutions/<target>.md`。

### A.4 错误答案集（模拟真实错法，每题一个）

- 实现题：用 `urllib.parse.quote` 代替 `encodeURIComponent` 语义；按码点而不是 UTF-16 码元排序或计长；hex 输出大写；
  漏掉 int32 截断；t5 漏掉一个环境依赖（例如 canvas 摘要）；t3 漏掉稀有分支；t4 的 `parse_token` 轮序弄反；t6 硬编码题面指纹。
- 结构题：把诱饵或别名 handler 计入 opcode 数；SUB/SHR 类 opcode 的操作数顺序弄反；密钥按小端/大端写反；把诱饵检测点当成生效检测点。
- 陷阱题：对答案为 none 的题给出一个"看起来像"的具体项；对提供了 none 选项但答案不是 none 的题答 none。
