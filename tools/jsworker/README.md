# jsworker（`jsw`）

用便宜模型（dsh 的 `js-worker` profile）在 Docker 沙箱里做 JS 逆向基准（目前是 `bench/jsvm1`）的一个目标。
设计依据是 `bench/jsvm1/HARNESS.md`；本目录是它的实现。

## 组成

| 文件 | 作用 |
|---|---|
| `jsw` | 命令行：`setup / doctor / run / resume / merge / gc` |
| `jsre_mcp.py` | MCP stdio 服务器，worker 唯一的工具来源（9 个工具），全部经 `docker exec` 在本 run 的容器里执行 |
| `jsre_helper.py` | 文件类工具在容器内的实现（以 `python3 -I -c` 方式送进容器，不在镜像里） |
| `profile/cordis.patch.yml` | dsh profile `js-worker` 的补丁层：关闭全部内置工具行和 `agent-instructions`、`skill-filesystem` |
| `image/` | 执行镜像 `jsvm1-tools:1`（`build.sh` 构建，镜像 id 写进 `image/IMAGE_DIGEST`） |
| `tests/` | 测试与夹具（`tests/fixtures/bench` 是一个两目标的小基准） |

dsh 的启动、`--patch` overlay、`--json` 事件流解析、超时杀进程组、profile 安装与检查复用
`tools/reworker/backend_dsh.py`（`JsBackend` 是它的子类）。

## 安装与自检

```sh
tools/jsworker/image/build.sh      # 构建镜像（只有这一步需要联网）
tools/jsworker/jsw setup           # 安装 ~/.dsh/profiles/js-worker
tools/jsworker/jsw doctor          # 全部 ok 才能跑
```

`doctor` 检查：dsh 可用；profile 补丁与仓库一致；合成配置里内置工具行全部关闭、只有 `mcp-jsre` 一个 MCP 行；
镜像存在且 id 等于 `IMAGE_DIGEST`；**暴露检查**：用假 LLM 服务器启动真实 profile 和真实 `jsre_mcp.py`，
记录 dsh 实际提供给模型的工具列表，必须恰好是下面 9 个，并在一次性容器里确认一次调用能执行、一次越界调用被拒。
暴露检查不调用真实模型。

## 跑一个目标

```sh
jsw run --target t3                                  # 默认：deepseek-v4.1-flash，effort max，2 h，400 次调用
jsw run --target t3 --model qwen4-max --effort high --timeout 3600 --max-calls 300
jsw run --target t1 --bench /path/to/other/bench     # 别的基准目录（布局相同）
```

流程：

1. **staging**：在 `tmp/jsw-runs/<run-id>/public/` 放 `README.md`、`tN/` 和只含 tN 题目的 `questions.json`；
   每个拷贝的文件都按 `public/MANIFEST.sha256` 校验，`tN/` 下有清单外的文件或符号链接就拒绝。`sealed/` 从不拷贝、从不挂载。
2. **容器**：`docker run --network none --read-only --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges
   --memory 4g --cpus 2 --pids-limit 128`，只挂 `public`（只读）和 `work`（读写）。启动后用 `docker inspect` 逐项核对，不符就不跑。
3. **dsh**：`dsh js-worker --patch overlay.yml --json -`，cwd 是空目录 `dsh-cwd/`，任务提示写在 `prompt.txt`。
4. **收尾**：在容器里对提交再跑一次 `submit_check`；把 `work/submission/` 导出到 `<run>/submission/`（只拷普通文件，
   **不跟随符号链接**）；审计；`docker rm -f`；写 `summary.json` 并打印。

退出码：0 完成且审计干净；1 worker 没正常结束（超时、出错）；2 没能启动；3 审计发现了按设计不可能发生的事。

### worker 的工具（模型看到的名字是 `mcp__jsre__*`）

`fs_list`、`fs_read`（支持 `unit="byte"` 字节窗口，单次 ≤ 40000 字节）、`fs_grep`（长行只显示命中点前后各 200 字节，并给出字节偏移）、
`fs_write`、`fs_edit`（只能写 `/task/work`）、`node_run`、`py_run`、`js_beautify`、`submit_check`。

- 路径必须是绝对路径，规范化后仍在 `/task` 下（写操作在 `/task/work` 下）；容器内再按 realpath 复查，worker 自建的符号链接也绕不出去。
- `node_run` 的 argv 由服务器拼：`node --permission --allow-fs-read=/task --allow-fs-read=/opt/jsre --allow-fs-write=/task/work
  [--stack-size=N] [--max-old-space-size=N] FILE ARGS`，其它 node 参数一律拒绝。
- `py_run`：`python3 -I -B -X utf8 /opt/jsre/pyrun.py FILE ARGS`（审计钩子禁子进程、socket、加载任意原生库；`-B` 不写 `__pycache__`，
  因为 `-I` 会忽略镜像里的 `PYTHONDONTWRITEBYTECODE`，同一秒内等长的修改会让旧字节码被复用）。`submit_check` 跑 `grade_runner.py` 时同样带 `-B`。
- 传 `code` 时代码先存成 `/task/work/.jsw/code/<n>.js|py` 再按文件运行。
- 程序输出合计超过 20000 字符时只返回头尾各一半，完整输出存到 `/task/work/.jsw/out/<n>.txt`。
- 每个容器内命令都包在 coreutils `timeout` 里（默认 60 s，上限 600 s）。
- **预算**：每次调用（含被拒的）占一个编号；用满 `--max-calls` 后执行类工具返回“请立即写提交”，
  `fs_write / fs_edit / submit_check` 还能再用 50 次，之后全部拒绝。计数从日志恢复，`resume` 后接着算。

### 产物（`tmp/jsw-runs/<run-id>/`）

```
run.json  prompt.txt  overlay.yml  events-N.jsonl  stderr-N.txt  attempts.json
tools.jsonl     每次工具调用一行：工具、参数、是否放行、编号、耗时、退出码、模型看到的文本、完整输出的存放路径
summary.json    状态、token、调用统计、导出的提交、最后一次 submit_check、审计结果
public/  work/  dsh-cwd/  dsh/（本 run 的 dsh session）
submission/     从 work/submission/ 导出的提交 —— 判分用这个，不要用 work/submission/
```

### 审计（`summary.json` 的 `audit`）

- `breaches`（任何一条都让退出码变 3）：事件流里出现非 jsre 工具的调用；事件流里完成的调用多于 `jsre_mcp.py` 执行过的；
  放行的调用带了 `/task` 外的路径；超预算执行；`jsre_mcp.py` 启动参数不是本 run 的；工具返回内容里出现 worker 没输入过的宿主路径；
  staging 与 `MANIFEST.sha256` 不一致或多出文件；容器配置与规格不符。
- `flags`（不影响退出码，值得看一眼）：被拒的越界路径；参数里出现宿主路径片段或 `sealed` 字样；`work/` 里指向 `/task` 外的符号链接。
- `notes`：模型调用了不存在的工具（dsh 已拒绝）、`jsre_mcp.py` fail-closed 退出、未导出的提交文件等。

## 续跑、合并、清理

```sh
jsw resume <run-id> [--prompt "..."] [--timeout 1800]   # 同一 staging、同名容器（重建）、同一 dsh session；预算接着算
jsw merge <run-id> <run-id> ... -o submission/          # 合并各目标导出的提交；qid 重叠或审计失败就拒绝（--force 放行后者）
python3 bench/jsvm1/sealed/grade.py submission/
jsw gc [--dry-run]                                      # 删除 jsw 进程已不在的 run 留下的容器
```

## 测试

都不调用真实模型。`test_unit.py` 不需要 Docker；其余需要镜像，`test_flow.py` 还需要 `jsw setup`。

```sh
python3 tests/test_unit.py      # 路径/参数策略、staging 与 MANIFEST、提示、overlay、导出、审计、merge、MCP 协议与预算
python3 tests/test_mcp.py       # 9 个工具在真实容器里的行为（字节窗口、grep 上下文、截断、submit_check 等）
python3 tests/test_escape.py    # 逃逸尝试必须全部被拒：宿主路径、../、写 public、网络、子进程、worker、ctypes、未知 node 参数……
python3 tests/test_flow.py      # 真实 dsh + 假 LLM：run、resume、merge、gc、doctor
```

## 已知限制

- dsh 每轮给模型的 session 提醒里会出现宿主上的 cwd（`.../jsw-runs/<run-id>/dsh-cwd`）和“file policy: read-only”字样；
  这是 dsh 自身行为，不影响 jsre 工具（它们不经过 dsh 的文件沙箱）。
- `py_run` 的审计钩子只是第二道防线（见 `image/sandbox_hook.py`），真正的边界是容器。已知绕过：
  直接调用 `_posixsubprocess.fork_exec(...)` 不触发任何审计事件，可以在容器内起子进程（仍然无网络、只读根、看不到宿主）。
- node 的 `--permission` 只检查传入的路径，不检查符号链接的目标（Node 文档写明的行为）。worker 可以先用 `py_run`
  建一个指向容器内其它位置的链接，再让 node 读它；能读到的只是镜像自带的文件（`py_run` 本来就能读），宿主文件不在容器里。
  `fs_*` 工具按容器内 realpath 复查，不受影响。
