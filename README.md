# retools

让大模型指挥便宜的小模型做 IDA 逆向细活的一套本地工具。主控模型拆任务、核验结论；小模型（“工人”）只能通过一个校验代理访问 IDA，只能调用固定的只读接口，交回带证据地址的 JSON。

出发点：通用模型做逆向的瓶颈在接口，不在模型。小模型猜 IDAPython API 容易错，所以把接口固定下来，并用机械手段限制它能做什么。

> **这是一份个人工具的快照，不是受维护的项目。** 它只在作者自己的机器上跑过（macOS、Apple Silicon）。Issues 已关闭，不接受功能请求，PR 不保证会看，没有版本号，也不承诺接口稳定。公开它是为了让设计和实测数据可以被查看和引用；要用的话请 fork。

## 部件

| 部件 | 做什么 | 文档 |
|---|---|---|
| `tools/rekit/` | IDA 内的只读紧凑视图：函数卡片、伪代码、引用、调用树、搜索、反汇编、密码常量比对，以及函数级仿真、整程序运行、计算草稿的入口 | `SKILL.md` |
| `tools/reworker/` | `rew` 命令：把一个窄任务派给工人，校验结果、审计调用、记入台账 | `SKILL.md` |
| `tools/remu/` | 函数级仿真器（Unicorn），吃 rekit 导出的内存镜像 | `README.md` |
| `tools/recalc/` | 受限的计算草稿：算术、哈希、分组密码、椭圆曲线，不用 `eval` | `README.md` |
| `tools/rebox/` | 整程序行为报告：`rebox run` 在 macOS 沙箱里仿真 PE（Speakeasy）和 ELF（Qiling）；`rebox live` 在断网 Docker 容器里真跑 ELF | `README.md`、`LIVE.md`、`SKILL.md` |
| `tools/jsworker/` | `jsw` 命令：同样的工人模式用于 JS 逆向，工具全部在 Docker 容器里执行 | `README.md` |

数据流：主控写任务 → `rew` 起一个无头的工人进程 → 工人只能通过校验代理访问 ida-mcp → 代理只放行 rekit 调用 → 工人交回 JSON → `rew` 校验、审计、记台账 → 主控抽查后标“已核验”或“驳回” → 已核验的结论出现在之后的函数卡片上。

设计取舍和已知问题见 [`docs/DESIGN.md`](docs/DESIGN.md)。

## 支持范围

- 宿主：macOS（Apple Silicon）。沙箱用 `sandbox-exec`，其他系统没有试过。
- 目标架构：x86、x86-64、ARM64。不支持 32 位 ARM 和 MIPS。
- 目标格式：PE、ELF、Mach-O 可做静态分析和函数级仿真；整程序运行只支持 PE（仿真）和 ELF（仿真或容器真跑）。

## 依赖

- IDA Pro 和 Hex-Rays 的 `ida-mcp` 命令（在 `PATH` 里，或用 `REW_IDA_MCP` 指定）
- [uv](https://docs.astral.sh/uv/)，Python 3.12
- 工人后端：DeepSeek Harness 的 `dsh` 命令行（用 `REW_DSH` 指定路径）和一个 OpenAI 兼容的模型端点
- `rebox live` 和 `jsworker` 需要 Docker

## 安装

```sh
git clone <this repo> retools && cd retools

# 1. 各工具自己的环境
for t in remu recalc rebox; do uv sync --frozen --project tools/$t; done
tools/rebox/rebox setup-elf          # 可选：ELF 仿真环境和 Linux 运行库，需要联网
tools/rebox/rebox live-setup         # 可选：ELF 真跑用的镜像

# 2. 把 skill 链接到你的 agent 能找到的位置
mkdir -p ~/.agents/skills
for s in rekit reworker rebox; do ln -sfn "$PWD/tools/$s" ~/.agents/skills/$s; done

# 3. 工人的模型端点
cp tools/reworker/profile/provider.example.yml tools/reworker/profile/provider.local.yml
$EDITOR tools/reworker/profile/provider.local.yml    # 填你自己的端点、密钥变量名、模型
tools/reworker/rew setup
tools/reworker/rew doctor            # 全部 ok 才能派工人
```

`provider.local.yml` 不进 git。三个 `SKILL.md` 里的路径按 `~/.agents/skills/<名字>` 写，所以第 2 步的链接位置要保持一致，或者自己改 skill 里的路径。

## 用法

```sh
# 派一个工人
tools/reworker/rew --db <样本或 .i64> --goal "……" --target 0x401000 --out r.json
# 整程序仿真（PE 或 ELF，不真跑）
tools/rebox/rebox run <样本>
# 在断网容器里真跑 ELF
tools/rebox/rebox live <样本.elf> [--fakenet]
```

IDA 里（ida-mcp 的 `execute_python`）：

```python
import sys; sys.path.insert(0, "<checkout>/tools/rekit")
import rekit; rekit.help()
```

运行记录写到 `tmp/`，台账写到 `findings/`，都不进 git。

## 测试

```sh
./test
```

一个入口跑全部测试集。需要 Docker 或真实 `dsh` 的测试集在条件不满足时会跳过并说明原因。

`./gc` 列出 `tmp/` 下可以清理的旧运行数据，加 `--apply` 才真的删除。

## 题库

`bench/` 下有三套盲测题，用来测整套流程而不只是工人：

| 目录 | 内容 |
|---|---|
| `bench/obf1/` | 6 个去符号的 ELF、58 道题：平坦化、不透明谓词、字节码虚拟机，以及带诱饵密钥和改动常量的 SM2/SM3/SM4/SHA-256/AES 程序 |
| `bench/obf2/` | 第二套混淆程序：6 个去符号的 ELF（x86-64 和 ARM64） |
| `bench/jsvm1/` | 6 个受保护的前端页面，要求还原请求签名或加密逻辑 |

题目都是纯计算、纯混淆的程序，没有恶意行为。仓库里只有 `public/`（题目和二进制）；源码、答案、评分脚本和出题说明不公开，否则题库就不能再用来做盲测。

在 `obf1` 上的成绩（53 道机器评分题）：

| | 得分 |
|---|---|
| 工人单独作答 | 47 |
| 修掉盲测查出的工具 bug 之后 | 48 |
| 再加上密码常量比对、整程序运行、计算草稿、精确值回填 | 52 |
| 整套流程（工人 + 主控核验） | 52，另一题是答案写法不在评分器列表里 |

## 安全说明

- `rebox run` 不执行样本的原生代码；外层进程会先自检沙箱确实生效再碰样本。
- `rebox live` 会真的执行样本。容器断网、零挂载、能力全丢，但容器不是恶意样本级别的隔离边界，详见 `tools/rebox/LIVE.md`。
- 两种模式都没有让样本真实联网的开关。
- 工人的“用途”类结论必须核验。实测里工人列出的事实基本可靠，定性容易出错。

## 许可证

本仓库的代码以 MIT 许可证发布，见 [`LICENSE`](LICENSE)。

运行时依赖由使用者自行安装，各有自己的许可证，其中 Unicorn 和 Qiling 是 GPL-2.0，Speakeasy 是 MIT。`rebox setup-elf` 下载的 Linux 运行库（glibc 等）不随仓库分发。
