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
`Job/Read`）读不到任何一个任务的配置文件，而任务如何定义在 API 的其他任何地方
都查不到。这样的扫描会对每个任务级控制项报告 `MANUAL`，运行时在 stderr 说明原因，
评分则把它们排除在外。这是诚实的结果；`scan.maxManual` 的存在，就是让 CI 可以
拒绝接受一次"看到的太少"的扫描。

同一条规则也决定了*未能完成*的扫描怎么办：退出码 2。没有 `Job/Read` 的 token
不会被拒绝读取任务列表 —— Jenkins 给它的是一个空列表；一个列不出内容的文件夹，
会让其中的任务悄无声息地从扫描里消失，连一个可报告的任务都不留下。两者都不是
干净的结果，也都不会以 0 退出。

## Token 能读到什么，报告才能说什么

对照 Jenkins 2.580.1 实测，[`hack/e2e`](hack/e2e) 里每一行都有对应账号：

| Token 权限 | 能回答的问题 |
| --- | --- |
| `Overall/Read` | 安全态势：认证、CSRF、匿名探针、内置节点的执行器、模式与标签、agent |
| + `Job/Read` | 任务列表、哪些任务被禁用。没有它，控制器会回答一个*空*列表，扫描以 2 退出 |
| + `Job/ExtendedRead` | 全部任务级控制项：任务如何定义、沙箱与 Groovy 脚本、触发器 |
| + `Overall/SystemRead` | 插件及其更新状态 —— 只读管理员，足以回答两条插件控制项 |
| + `Credentials/View`（`Overall/Administer` 隐含） | 控制器自身凭据存储里的凭据元数据 |

推荐的扫描账号是 `Overall/Read`、`Job/Read`、`Job/ExtendedRead` 加
`Overall/SystemRead`：它能回答每一条自动化控制项，却改不了任何东西。
`Job/ExtendedRead` 与 `Overall/SystemRead` 是需要显式开启的权限 —— 启动控制器时
加上 `-Dhudson.security.ExtendedReadPermission=true` 与
`-Djenkins.security.SystemReadPermission=true` 才能授予。在按文件夹授权的环境里，
token 只看得到它有权读的文件夹；看不到的文件夹对它而言不存在，而不是报错。

请使用 API token（*People → 用户 → Security → API Token*），不要用密码。
每个请求都是 GET —— 由测试保证，由客户端的 transport 拒绝其他方法，并在每次扫描
结束时清点：

```
[INFO] ✓ 31 requests · 31 GET · 0 writes · read-only
```

快照从构造上就不含任何密文：触发 token 只记录存在与否，绝不记录值；嵌在 SCM URL
里的凭据在保存任何东西之前就被剥离；所以 `--snapshot-out` 的文件可以放心附在
bug 报告里。

## 安装

```sh
go install github.com/scm-bench/jenkins-bench/cmd/jenkins-bench@latest
```

或从 [Releases](https://github.com/scm-bench/jenkins-bench/releases)
下载归档，或使用容器镜像。

## 快速上手

```sh
# 扫描控制器。凭据也可以来自环境变量：
# JENKINS_URL、JENKINS_USER、JENKINS_TOKEN；命令行参数优先于环境变量。
jenkins-bench scan --url https://jenkins.example.com --username audit --token $TOKEN

# 展开每个任务的发现与完整修复步骤。
jenkins-bench scan ... --details

# 缩小扫描范围：某个文件夹下的全部任务，或某一个任务，均按完整名称。
# 两者可重复、可叠加；控制器不认识的名称以 2 退出。
jenkins-bench scan ... --folder platform/backend --job release/deploy-prod

# 实时查看每一个请求。
jenkins-bench scan ... -v

# 保留快照，之后离线追问，无需再次扫描。
jenkins-bench scan ... --snapshot-out jenkins.json
jenkins-bench scan --snapshot-in jenkins.json --details

# 机器格式，用于 CI、代码扫描与测试视图 —— 写入文件，权限 0600、原子写入。
jenkins-bench scan ... -o json  --output-file report.json
jenkins-bench scan ... -o sarif --output-file jenkins.sarif
jenkins-bench scan ... -o junit --output-file jenkins-bench.xml

# 写出一份每个默认值都写明的带注释配置。
jenkins-bench init
```

`--format` 是 `-o` 的旧名称，仍然可用，并会提示它已弃用。

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 扫描完成，且没有越过任何阈值 |
| `1` | 越过了某个阈值 —— `scan.failOn`（有这么严重的失败吗？）、`scan.failUnder`（分数可以接受吗？）或 `scan.maxManual`（扫描看到的东西够形成判断吗？） |
| `2` | 扫描未能完成：控制器读不到、凭据被拒绝、`--folder` 或 `--job` 指定的目标不存在、某条策略评估失败、**没有评估任何任务**，或**任务列表不完整** |

一次没有评估任何任务的扫描 —— token 没有 `Job/Read`，或控制器上本就没有任务 ——
以 2 退出：没有审计任何任务级内容，绿色的 CI 步骤不能声称相反。某个文件夹列不出
内容时，扫描仍会写出报告，在扫描警告里点名每一个漏掉的文件夹，把 SARIF 运行标记为
未成功执行，并以 2 退出，除非 `scan.allowIncomplete: true` 书面接受这次部分扫描。

例外（见下文）让被接受的失败不再触发 `scan.failOn`，让被接受的 MANUAL 不再计入
`scan.maxManual`；它既不改变发现本身，也不改变分数。

每次扫描都会说出它读取的配置文件 —— stderr 上的 `using config jenkins-bench.yaml`
—— 这样，被门禁的 pull request 往工作目录里放进一份配置文件，也无法悄悄改变门禁。

## 在 CI 中使用

阈值写在与流水线一起提交的 `jenkins-bench.yaml` 里，这样流水线与笔记本读的是同一
个文件，不会有任何分歧。

**GitHub Actions** —— 把 SARIF 上传到代码扫描。它是代码扫描既接受、也展示的格式：
每个结果都带物理位置（`jenkins/<host>/<任务完整名称>`，不必真实存在于仓库中），
MANUAL 结果从不显示为某个严重程度，运行按控制器分类。扫描发现问题时以 `1` 退出 ——
这正是它的用处 —— 但那会在上传之前结束作业，所以把失败推迟到最后一步。上传需要在
作业的 `permissions` 里给出 `security-events: write`；在私有仓库里还需要
`actions: read` 与 `contents: read`。为每台控制器指定自己的 `category`，这样两台
控制器上传到同一个仓库时不会互相关闭对方的告警：

```yaml
- name: Audit Jenkins
  id: audit
  continue-on-error: true
  run: jenkins-bench scan -o sarif --output-file jenkins.sarif
  env:
    JENKINS_URL: https://jenkins.example.com
    JENKINS_USER: audit
    JENKINS_TOKEN: ${{ secrets.JENKINS_TOKEN }}

- name: Upload to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: jenkins.sarif
    category: jenkins-bench/jenkins.example.com

- name: Fail the job if the audit did
  if: steps.audit.outcome == 'failure'
  run: exit 1
```

代码扫描每次运行最多保留 5,000 个结果，SARIF 也照此截断 —— 最严重的优先 —— 并说明
扣下了多少；`-o json` 包含全部发现。

**Jenkins** —— JUnit 发布器把结果画在构建自己的测试视图里，每条控制项一个测试套件、
每个任务一个测试用例：

```groovy
stage('Audit Jenkins') {
  steps {
    withCredentials([string(credentialsId: 'jenkins-bench-token', variable: 'JENKINS_TOKEN')]) {
      sh '''
        jenkins-bench scan --url https://jenkins.example.com --username audit \
          -o junit --output-file jenkins-bench.xml
      '''
    }
  }
  post {
    always {
      // 只负责展示报告；构建结果已由扫描的退出码决定。
      junit testResults: 'jenkins-bench.xml', allowEmptyResults: true, skipMarkingBuildUnstable: true
    }
  }
}
```

**Azure Pipelines** —— 同一个文件，通过 `PublishTestResults`：

```yaml
- script: |
    jenkins-bench scan --url "$(JENKINS_URL)" --username audit -o junit --output-file jenkins-bench.xml
  displayName: Audit Jenkins
  env:
    JENKINS_TOKEN: $(JENKINS_TOKEN)
- task: PublishTestResults@2
  condition: succeededOrFailed()
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: jenkins-bench.xml
    failTaskOnFailedTests: false   # 门禁是扫描的退出码
```

在每一种配方里，都是扫描的退出码决定构建，报告只负责展示。测试报告承担不了门禁：
JUnit 没有严重程度的概念，每个未被接受的 `FAIL` 都是一个失败的测试 —— 包括 `LOW` ——
任由发布器按失败测试判定构建，门禁就会比 `scan.failOn` 更严。而丢弃扫描退出码的写法
—— `returnStatus: true`、`|| true` —— 会放过越过的 `scan.maxManual` 或
`scan.failUnder`，连退出码 2 也一并放过：结果是一个黄色的构建（Jenkins 的 `junit`
步骤把失败的测试标为 `UNSTABLE` 而非失败），或者在恰好没有测试失败时，是一个绿色的
构建。报告会在能说的地方自己说明 —— 无法为覆盖范围担保的扫描会把 SARIF 运行标记为
未成功，并在 JUnit 文件里加入失败的 `scan` 用例 —— 但只有退出码覆盖所有情况。

## 大型控制器

- **缩小范围。** `--folder` 与 `--job` 只读取它们点名的内容；只负责一个文件夹的
  团队，既不必等其余部分扫完，也不必持有能读其余部分的 token。
- **每个任务只花一个请求**，即它的 `config.xml`；其余每个端点都只请求扫描用得到的
  字段。`scan.concurrency`（默认 8）限制并发请求数，`scan.timeout`（默认 30s）
  限制单个请求，`scan.maxDuration` 限制整次扫描。
- **评估不是瓶颈**：一台有 1,000 个 agent 的控制器、10,000 个任务的快照，在笔记本
  上不到三秒评估完。
- **对上千个任务使用 `--details` 就是上千个小节**；`--max-resources` 设上限，
  并说明省略了多少。
- 保留快照（`--snapshot-out`），用 `--snapshot-in` 离线追问，而不是再扫一遍。

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

有三条控制项读取的内容比名字所示更多，因为显而易见的读法会产生误判为通过：

- **CIS-2.3.5** 对任何绕过 Jenkins 逐用户授权即可启动构建的触发方式判为失败 ——
  核心的远程触发 token，*以及* Generic Webhook Trigger（其端点无需登录）；对未曾
  学过的触发器类、以及触发器写在各分支 Jenkinsfile 里的多分支项目，报告 `MANUAL`。
- **CIS-2.3.1** 依据多分支项目的分支工厂（branch factory）判断：脚本来自控制器的
  工厂（inline-pipeline，或 Config File Provider 文件）与内联流水线一样判为失败。
- **CIS-2.1.2** 对任务中任何位置的沙箱外 Groovy 判为失败 —— System Groovy 步骤、
  Groovy Postbuild 发布器、Active Choices 参数、Job DSL 步骤 —— 而不只是内联流水线。

匿名探针不跟随任何重定向，只把 Jenkins API 本身算作回答：在需要认证的代理之后，
它报告 `MANUAL` 并说明请求被转去了哪里。插件是否"最新"是相对控制器自身内核版本
所在的更新中心层级而言的：在旧内核上，"最新"指该内核能运行的最新插件。

## 评分

```
score = floor(Σ weight(passed) / Σ weight(passed + failed) × 100)
```

其中 `HIGH = 3`、`MEDIUM = 2`、`LOW = 1`。`MANUAL` 与 `NA` 不进入任何一侧。
向下取整，绝不四舍五入，所以有失败项时分数绝不会显示为 `100`。算式随分数一起
打印，让这个数字可以被验算。当没有任何可判定项时，分数是
`0` 而不是 `100` —— 空分子除以空分母绝不能读作一份健康证明。

## 配置

`jenkins-bench init` 写出一份每个默认值都写明的带注释 `jenkins-bench.yaml`；
`scan` 会自己找到它（并在 stderr 上说出来）。一次性的覆盖不需要文件：
`--set scan.failOn=none`。参考 [`examples/config.yaml`](examples/config.yaml)。

### 传输

- **内部 CA**：`scan.caFile: /etc/ssl/certs/corp-root-ca.pem` 指定一个 PEM 证书包，
  *在系统根证书之外*额外信任。启动时即检查 —— 文件缺失或其中没有证书时以 2 退出 ——
  这才是内部 CA 后面的控制器需要的设置，而不是完全不检查对方身份的 `scan.insecure`。
  两者不能同时设置。
- **代理**：遵循 `HTTPS_PROXY`、`HTTP_PROXY` 与 `NO_PROXY`，与所有 Go 工具一致。
- **明文**：指向本机以外地址的 `http://` URL 会被拒绝，除非 `scan.allowPlaintext: true`
  书面允许。
- **重定向**只在控制器的同源（scheme、host、port）内跟随，最多五次，token 绝不会被
  带到别处；从 https 降级到 http 的重定向是一个点名两端 URL 的错误。

### 例外

组织决定接受的发现 —— 有明确理由、有明确期限 —— 在配置中声明：

```yaml
exceptions:
  - control: CIS-2.3.5              # 精确的控制项 ID
    resources: [platform/legacy-*]   # 匹配任务完整名称的通配符；* 不跨越 "/"；
                                     # 控制器级控制项用 "controller"
    reason: Vendor job, replaced in Q1
    owner: platform-team@example.com # 可选
    expires: 2027-03-31              # 当天（UTC）结束前有效
```

被接受的发现仍然会被报告（在"Accepted by exceptions"之下），仍然是 `FAIL`，
仍然计入分数：分数描述的是控制器，接受一个发现并不会改变控制器。它不再做的，
是因 `scan.failOn` 让运行失败 —— 对 `MANUAL` 发现而言，是不再计入 `scan.maxManual`。
JSON 在发现上带有豁免信息，SARIF 带有代码扫描显示为"已忽略"并附理由的 suppression，
JUnit 则是被跳过的测试用例。过期或已经不匹配任何发现的例外，每次运行都会被报告，
这样清单不会悄悄地腐烂。

## 工作原理

```
Jenkins API ──► fetcher ──► snapshot.json ──► Rego 策略 ──► 报告
             （只发 GET）   （归一化、无密文）（每控制项一条） table/json/sarif/junit
```

捕获与评估是分离的：在持有 token 的 runner 上取得的快照，可以在别处、
稍后、离线且无 token 地重新评估，得到逐字节一致的发现。快照带有 schema 版本；
本版本读取第 2 版，拒绝更早的快照 —— 其结构缺少当前控制项据以判断的内容，
升级后请重新捕获。

所有版本相关或琐碎的东西 —— 标签表达式、定义类名与分支工厂、哪些触发器绕过授权、
自称 1.1 版的 XML —— 都在 fetcher 里用 Go 解决，规则只问"这个任务能在控制器上
跑吗？"，从不问"`built-in && linux` 匹配这个节点吗？"。

## 它实现的规范

本 bench 遵循家族的通用
[bench 契约](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
—— 同样的四种状态、同样的 `metadata.json`、同样的评分、同样的报告格式外加 JUnit ——
并发布了 [Jenkins 领域快照 schema](https://github.com/scm-bench/scm-bench/blob/main/docs/jenkins-snapshot.md)，
这是家族里的第二套领域 schema，也是第一个源码托管之外的领域。本版本的快照是第 2 版，
领先于仍在描述第 1 版的已发布 schema。

这里的 `FAIL` 与 [bitbucket-bench](https://github.com/scm-bench/bitbucket-bench)
的 `FAIL` 含义完全相同。

## 参与贡献

从 [CONTRIBUTING.md](CONTRIBUTING.md) 开始。最有价值的贡献是拿它对着一台
真实控制器跑一遍，报告不符之处：对着替身服务器测试过的 fetcher 只证明了
自洽，不证明与真实平台一致。`hack/recon/` 里是测出本工具对 Jenkins API
全部认知的那套装置，任何论断都可以复查，而不必信任；[`hack/e2e/`](hack/e2e)
则启动一台每条控制项都处于已知状态的控制器，针对每一种 token，把每个判定与
夹具的真实情况逐一核对。

## 许可

Apache 2.0，见 [LICENSE](LICENSE)。

<sub>与 CIS 及 Jenkins 项目均无隶属关系。</sub>
