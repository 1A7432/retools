# jsvm1：前端 JS 逆向题

虚构站点“潮汐票务”的六个前端页面，每个页面的脚本都经过保护。你的任务是还原请求签名或加密逻辑，用 Python 复现，并回答 `questions.json` 中的问题。
所有页面、接口、密钥和算法都是虚构的；`*.invalid` 域名不存在，不要尝试联网。

## 目录

| 目录 | 内容 |
|---|---|
| `t1/` … `t6/` | `index.html`（页面外壳）、`app.js`（受保护的脚本）、`samples.json`（抓包样本）；t5、t6 另有 `fingerprint.json` |
| `questions.json` | 全部题目。每题有 `id`、`target`、`question`、`answer_format`、`difficulty`；实现题另有 `impl` 字段 |

## 签名函数通用约定

除非题面另有说明，所有形如 `sign(params, ts, nonce)` 的函数都遵守以下约定：

- `params`：`dict[str, str]`。键和值都是合法的 Unicode 字符串（不含孤立的代理项），可以为空串；键不会是 `"__proto__"`；字典可以为空。
  页面把它当作普通 JS 对象，键值对的先后顺序对结果没有影响。
- `ts`：`int`，毫秒时间戳，`0 ≤ ts < 2^53`。页面中它就是 `Date.now()` 的返回值，请求头 `X-Tw-Ts` 是它的十进制字符串。
- `nonce`：16 个小写十六进制字符。页面用 `crypto.getRandomValues` 填充 8 个字节，按下标顺序逐字节写成两位小写十六进制，结果即请求头 `X-Tw-Nonce`。
- 返回值：页面实际发出的那个请求头或字段的值，逐字符相同，大小写敏感。

## 参考浏览器（t5、t6）

t5、t6 的签名依赖浏览器环境。“参考浏览器”或“干净浏览器”指：

- 未被修改的桌面版 Chrome，开发者工具未打开，没有扩展；
- 所有内置对象和函数都是原生实现，没有被替换或包装；
- 不存在 Node.js 的 `process` 等对象；
- `navigator`、`screen` 的取值由 `fingerprint.json`（t5）或 `env` 参数（t6）给出；
- 页面绘制的 canvas 调用 `toDataURL()` 时，返回 `canvas` 字段给出的字符串；
- `Date.prototype.getTimezoneOffset()` 对任意日期都返回 `timezoneOffset`；
- `fingerprint.json` 中的 `screenWidth`、`screenHeight` 分别对应 `screen.width`、`screen.height`，`availWidth`、`availHeight` 对应 `screen.availWidth`、`screen.availHeight`，其余字段名与 `navigator` 上的属性名相同。

### t6 环境参数

T6-01 的 `env` 是一个 dict，键与 `t6/fingerprint.json` 完全相同：

| 键 | 类型与取值范围 | 对应的浏览器值 |
|---|---|---|
| `userAgent`、`language`、`platform` | 任意字符串 | `navigator` 上的同名属性 |
| `hardwareConcurrency` | 1–128 的整数 | `navigator.hardwareConcurrency` |
| `deviceMemory` | 1、2、4、8、16、32 之一 | `navigator.deviceMemory` |
| `screenWidth`、`screenHeight` | 1–10000 的整数 | `screen.width`、`screen.height` |
| `colorDepth` | 8、16、24、30、32、48 之一 | `screen.colorDepth` |
| `timezoneOffset` | −840–720 的整数 | `Date.prototype.getTimezoneOffset()` 的返回值 |
| `canvas` | 任意字符串 | 页面 canvas 的 `toDataURL()` 返回值 |
| `webdriver` | `true` 或 `false` | `navigator.webdriver` |

## 抓包样本

`tN/samples.json` 的格式为 `{"<题号>": [{"args": [...], "out": ...}, ...]}`。`args` 是该题函数的位置参数，`out` 是页面在这组输入下的真实输出。样本只覆盖普通输入。

## 提交格式

把答案放在 `/task/work/submission/` 目录下：

```
submission/
  answers.json     {"T1-02": "…", "T3-03": 84, "T5-02": ["A", "C"], "T3-08": "none", "T1-01": "T1-01.py", …}
  T1-01.py         每道实现题一个文件，文件名 = 题号 + ".py"
```

- 非实现题：整数可以写成十进制数或 `"0x…"` 字符串；十六进制答案不区分大小写，可带 `0x` 前缀；列表写成 JSON 数组；
  “没有/不存在/都不是”一类答案写 `"none"`；JSON 对象类答案按题面给出的键名填写。
- 实现题：`answers.json` 里该题的值写文件名。Python 3.13，只能使用标准库、`pycryptodome`（`Crypto`）和 `gmssl`；
  不得访问网络、文件或启动子进程；每次调用限时 2 秒；必须是确定性的。
  判分时用大量隐藏测试向量逐组比较，覆盖空串、超长输入、各类 Unicode 字符、特殊 ASCII 字符和 ts 的边界值，只有全部一致才算对。
- 可以随时用 `submit_check` 工具检查提交格式，并用公开样本试跑实现题。
