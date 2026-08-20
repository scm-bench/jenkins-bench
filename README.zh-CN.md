<!--
  横幅图与英文版共用 scm-bench/.github (brand/) 里的一份文件。
  本文件是 README.md 的人工同步译本，供快速了解之用；如与英文版有出入，
  以英文版为准 —— 控制项元数据与报告输出本身只有英文。
-->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-jenkins-bench-dark-1760x440.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-jenkins-bench-light-1760x440.png">
    <img src="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-jenkins-bench-light-1760x440.png" alt="jenkins-bench" width="880">
  </picture>
</p>

依据 [CIS 软件供应链安全指南](https://www.cisecurity.org/benchmark/software-supply-chain-security)
的 **Build Pipelines** 章节，审计一台 **Jenkins 控制器**。

[English](README.md)

jenkins-bench 以**只读**方式捕获控制器的快照 —— 任务、凭据、agent 与插件 ——
用 Rego 策略逐项评估，然后告诉你哪里配置有误，以及修复它的确切设置路径。

```
jenkins-bench scan --url https://jenkins.example.com --username audit --token <api-token>
```

## 最值得了解的一条设计决定

**无法评估的控制项报告 `MANUAL`，绝不报告 `PASS` 或 `FAIL`。**
扫描不会因为一个它问不出口的问题获得加分，也不会因此被扣分。

这条规则在 Jenkins 上立刻显出分量：一个最小权限 token（`Overall/Read` 加
`Job/Read`，即扫描账号应有的权限）读不到任何一个任务的配置文件，而任务如何定义
在 API 的其他任何地方都查不到。这样的扫描会对每个任务级控制项报告 `MANUAL`，
运行时在 stderr 说明原因，评分则把它们排除在外。这是诚实的结果；`scan.maxManual`
的存在，就是让 CI 可以拒绝接受一次"看到的太少"的扫描。

## Token 能读到什么，报告才能说什么

| Token 权限 | 能回答的问题 |
| --- | --- |
| `Overall/Read` | 安全态势：认证、CSRF、匿名探针、执行器、agent |
| + `Job/Read` | 任务列表、哪些任务被禁用 |
| + `Job/ExtendedRead` | 全部任务级控制项：任务如何定义、沙箱、触发 token |
| + `Overall/Administer` | 插件及其更新状态、凭据元数据 |

请使用 API token（*People → 用户 → Security → API Token*），不要用密码。
每个请求都是 GET —— 由测试保证，而非约定 —— 且快照从构造上就不含任何密文：
任务的远程触发 token 只记录存在与否，绝不记录值，所以 `--snapshot-out`
的文件可以放心附在 bug 报告里。

## 安装

```sh
go install github.com/scm-bench/jenkins-bench/cmd/jenkins-bench@latest
```

或从 [Releases](https://github.com/scm-bench/jenkins-bench/releases)
下载归档，或使用容器镜像。

## 快速上手

```sh
# 扫描控制器。凭据也可以来自环境变量：
# JENKINS_URL、JENKINS_USER、JENKINS_TOKEN。
jenkins-bench scan --url https://jenkins.example.com --username audit --token $TOKEN

# 展开每个任务的发现与完整修复步骤。
jenkins-bench scan ... --details

# 保留快照，之后离线追问，无需再次扫描。
jenkins-bench scan ... --snapshot-out jenkins.json
jenkins-bench scan --snapshot-in jenkins.json --details

# 机器格式，用于 CI 与代码扫描。
jenkins-bench scan ... --format json
jenkins-bench scan ... --format sarif

# 写出一份每个默认值都写明的带注释配置。
jenkins-bench init
```

退出码：`0` 干净，`1` 越过了某个阈值，`2` 扫描未能完成。驱动退出码 `1`
的三个设置回答三个不同的问题：`scan.failOn`（有这么严重的失败吗？）、
`scan.failUnder`（分数可以接受吗？）、`scan.maxManual`（扫描看到的东西够
形成判断吗？）。

## 覆盖范围

指南第 2 章共 28 条控制项。并非每条都能从控制器的 API 得到答案 ——
有几条显而易见的候选，任何工具都答不了，因为 API 根本不暴露它们问的东西。
覆盖表选择完整而不是悄悄地缺页：无法自动化的控制项以手工形式收录，
其文字说明答案实际在哪里。完整覆盖表见[英文版 README](README.md#coverage)。

自动化 8 条，手工 7 条。其中 `JENKINS-PLUGIN-UPDATES` 特意不带 CIS 编号：
指南没有"保持 CI 系统自身组件最新"的条目，借用邻近编号会让基准映射变得
不诚实。它作为补充控制排在映射控制之后。

侦察阶段还淘汰了两条只会永远 PASS 的候选（旧版 agent 协议、Agent → Controller
访问控制 —— 两者在当前 LTS 上都是强制开启的）。证据在
[`docs/jenkins-api-notes.md`](docs/jenkins-api-notes.md)，那份文档记录了
Jenkins API 会告诉你什么、不会告诉你什么 —— 全部实测，而非转述文档。

## 评分

```
score = Σ weight(passed) / Σ weight(passed + failed) × 100
```

其中 `HIGH = 3`、`MEDIUM = 2`、`LOW = 1`。`MANUAL` 与 `NA` 不进入任何一侧，
算式随分数一起打印，让这个数字可以被验算。当没有任何可判定项时，分数是
`0` 而不是 `100` —— 空分子除以空分母绝不能读作一份健康证明。

## 工作原理

```
Jenkins API ──► fetcher ──► snapshot.json ──► Rego 策略 ──► 报告
             （只发 GET）   （归一化、无密文）（每控制项一条） table/json/sarif
```

捕获与评估是分离的：在持有 token 的 runner 上取得的快照，可以在别处、
稍后、离线且无 token 地重新评估，得到逐字节一致的发现。所有版本相关或
琐碎的东西 —— 标签表达式、定义类名、自称 1.1 版的 XML —— 都在 fetcher 里
用 Go 解决，规则只问"这个任务能在控制器上跑吗？"，从不问
"`built-in && linux` 匹配这个节点吗？"。

## 它实现的规范

本 bench 原封不动地遵循家族的通用
[bench 契约](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
—— 同样的四种状态、同样的 `metadata.json`、同样的评分、同样的三种报告格式 ——
并发布了 [Jenkins 领域快照 schema](https://github.com/scm-bench/scm-bench/blob/main/docs/jenkins-snapshot.md)，
这是家族里的第二套领域 schema，也是第一个源码托管之外的领域。

这里的 `FAIL` 与 [bitbucket-bench](https://github.com/scm-bench/bitbucket-bench)
的 `FAIL` 含义完全相同。

## 参与贡献

从 [CONTRIBUTING.md](CONTRIBUTING.md) 开始。最有价值的贡献是拿它对着一台
真实控制器跑一遍，报告不符之处：对着替身服务器测试过的 fetcher 只证明了
自洽，不证明与真实平台一致。`hack/recon/` 里是测出本工具对 Jenkins API
全部认知的那套装置，任何论断都可以复查，而不必信任。

## 许可

Apache 2.0，见 [LICENSE](LICENSE)。

<sub>与 CIS 及 Jenkins 项目均无隶属关系。</sub>
