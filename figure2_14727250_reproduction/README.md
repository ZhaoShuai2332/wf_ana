# 14727250 数据集 Figure 2 风格复现实验

本目录是一套独立的运行入口，用于在 `14727250` 数据集上尽可能复现论文
*Understanding Web Fingerprinting with a Protocol-Centric Approach* 中 Figure 2 的实验思路。

## 与原论文方法的对应关系

原论文 Figure 2 的核心对象是单条 HTTPS flow 内的 payload/clump 位置：

```text
F = (P0, P1, P2, ...)
Phead(i) = (P0, ..., Pi)
Ptail(i) = (Pi, ..., PN)
```

原仓库中对应的实现主要分布在：

- `crawlers/src/tls_crawler/processing/features/time_series.py`
  - `TimeSeries._clumps()`：按方向变化将 TLS/QUIC 包聚合为 clump。
  - `TimeSeries.data()`：输出 `relative_timestamp, duration, length, pkt_count, direction`。
- `experiments/domains_experiments/crawler/process.py`
  - 调用 `process_pcap(...).temporal_stats_per_flow()` 得到每条 flow 的时序特征。
- `experiments/domains_experiments/scripts/evaluate_datasets_by_timepoint.py`
  - `X[:, :horizon, :]` 对应保留头部位置。
  - `X[:, horizon:, :]` 对应保留尾部位置。

本目录的脚本 `reproduce_figure2_14727250.py` 沿用这一思路，但针对 `14727250` 的目录结构做了适配：

1. 遍历 `14727250/result_*/pcap/*.pcap`。
2. 根据同目录下的 `domain_ip/*.csv` 查找目标站点相关 IP。
3. 从一次访问中选择一条目标 443 连接，默认选择目标 IP 中总载荷最大的连接。
4. 在该连接内部按方向变化聚合 pseudo-payload/clump，得到 `P0/P1/P2/...`。
5. 构造 `Phead(i)` 与 `Ptail(i)`。
6. 使用交叉验证计算 macro-F1、weighted-F1 和 per-site F1。
7. 以小提琴图形式绘制 Figure 2 风格结果。

注意：这里的 `P_i` 是从 PCAP 可见载荷中构造的 `pseudo-payload/clump`，不保证严格对应 TLS 协议消息。更严谨的表述是：

```text
14727250 数据集上的 Figure-2-style pseudo-payload position contribution analysis
```

不应直接写成：

```text
严格复现 TLS P0/P1/P2 协议阶段
```

## 输出目录

默认输出到：

```text
figure2_14727250_reproduction/outputs/
```

主要文件包括：

- `features/pseudo_payload_features.csv`
  - 每个访问样本选中的目标连接及其 `P0/P1/...` 序列。
- `features/site_coverage.csv`
  - 各站点样本数及是否进入监督评估。
- `features/extraction_failures.csv`
  - PCAP 解析失败、无 443 载荷、无可选连接等失败原因。
- `features/feature_summary.csv`
  - 每个样本的 P-like 位置数量、目标连接大小、连接持续时间等。
- `metrics/model_metrics.csv`
  - 完整 P 序列下不同模型的分类性能。
- `metrics/figure2_metrics.csv`
  - 每个 `Phead/Ptail` 位置的性能。
- `metrics/figure2_per_site_f1.csv`
  - 绘制小提琴图使用的 per-site F1 分布。
- `metrics/critical_window_summary.csv`
  - 按 `full_f1_macro - critical_threshold` 推断的关键窗口。
- `metrics/position_stage_summary.csv`
  - 每个 `P_i` 的覆盖率、长度、方向和保守阶段解释。
- `plots/figure2_pseudo_payload_positions.png`
  - Figure 2 风格复现图。
- `README.md`
  - 脚本自动生成的本轮结果摘要。

## 参数说明

| 参数 | 默认值 | 含义 |
|---|---:|---|
| `--stage` | `all` | `all` 运行完整流程；`process` 只抽特征；`evaluate` 只评估；`plot` 只按已有指标重画图；`report` 只生成报告。 |
| `--input` | `14727250` | 14727250 数据集目录。 |
| `--output-dir` | `figure2_14727250_reproduction/outputs` | 结果输出目录。 |
| `--features` | `outputs/features/pseudo_payload_features.csv` | 中间特征 CSV 路径。 |
| `--port` | `443` | 分析的服务端端口。 |
| `--length-mode` | `transport-payload` | 使用 TCP/UDP 载荷长度；`frame` 表示整帧长度，更贴近原仓库 `len(packet)`。 |
| `--flow-selector` | `target-largest` | 目标连接选择策略。 |
| `--target-domain-mode` | `exact-or-subdomain` | `domain_ip` 中目标域名匹配方式。 |
| `--sequence-width` | `20` | 每个样本最多保留多少个 `P_i`。 |
| `--window-size` | `20` | 绘图时评估到 `P0..P19`。 |
| `--feature-set` | `paper` | `paper` 使用原仓库风格五元组；`signed` 使用带方向的大小；`rich` 增加 log 和起始时间。 |
| `--models` | `logistic_regression,random_forest,knn,xgboost` | 参与完整序列评估的模型；`all` 表示全部。 |
| `--primary-model` | `auto` | 用于画 `Phead/Ptail` 的模型；`auto` 选择完整序列 macro-F1 最高模型。 |
| `--evaluation-mode` | `multiclass` | 多分类评估；`one-vs-rest` 更接近原论文逐域名二分类，但很慢。 |
| `--min-samples-per-site` | `5` | 进入监督评估的站点最少样本数。 |
| `--max-folds` | `5` | 分组交叉验证最大折数。 |
| `--critical-threshold` | `0.02` | 关键窗口阈值：完整 macro-F1 减去该值。 |
| `--model-preset` | `standard` | `high` 会增加模型训练规格，运行更慢。 |
| `--reuse-features` | 关闭 | 复用已存在特征文件，跳过 PCAP 解析。 |
| `--site-limit` | `0` | 调试用，只处理前 N 个站点；0 表示不限制。 |
| `--max-visits-per-site` | `0` | 调试用，每个站点最多保留多少次访问；0 表示不限制。 |
| `--workers` | `1` | PCAP 解析并行线程数；全量处理可设置为 4 或 8。 |

## 快速验证命令

用于检查环境和流程是否能跑通：

```powershell
python figure2_14727250_reproduction\reproduce_figure2_14727250.py `
  --stage all `
  --input 14727250 `
  --output-dir figure2_14727250_reproduction\outputs_smoke `
  --features figure2_14727250_reproduction\outputs_smoke\features\pseudo_payload_features.csv `
  --site-limit 8 `
  --max-visits-per-site 6 `
  --workers 1 `
  --window-size 8 `
  --sequence-width 8 `
  --models logistic_regression `
  --primary-model logistic_regression `
  --min-samples-per-site 3 `
  --max-folds 3
```

## 完整运行命令

使用全部 14727250 PCAP，并对完整序列运行多个模型，自动选择最佳模型绘制 Figure 2 风格图：

```powershell
python figure2_14727250_reproduction\reproduce_figure2_14727250.py `
  --stage all `
  --input 14727250 `
  --output-dir figure2_14727250_reproduction\outputs_full `
  --features figure2_14727250_reproduction\outputs_full\features\pseudo_payload_features.csv `
  --length-mode transport-payload `
  --flow-selector target-largest `
  --target-domain-mode exact-or-subdomain `
  --feature-set paper `
  --sequence-width 20 `
  --window-size 20 `
  --models all `
  --primary-model auto `
  --evaluation-mode multiclass `
  --min-samples-per-site 5 `
  --max-folds 5 `
  --critical-threshold 0.02 `
  --model-preset standard `
  --workers 8
```

## 更贴近原论文但计算更重的命令

原论文更接近逐域名 one-vs-rest 评估。该模式会显著增加训练次数：

```powershell
python figure2_14727250_reproduction\reproduce_figure2_14727250.py `
  --stage evaluate `
  --input 14727250 `
  --output-dir figure2_14727250_reproduction\outputs_full_ovr `
  --features figure2_14727250_reproduction\outputs_full\features\pseudo_payload_features.csv `
  --feature-set paper `
  --sequence-width 20 `
  --window-size 20 `
  --models logistic_regression `
  --primary-model logistic_regression `
  --evaluation-mode one-vs-rest `
  --min-samples-per-site 5 `
  --max-folds 5 `
  --critical-threshold 0.02
```

## 只按 Figure 2 阶段命名重画横轴

如果已经完成评估，只想把横轴更新为 `P0: Client Hello`, `P1: Server Hello`, `P2: Client Req.` 这类 Figure 2 风格标签，可运行：

```powershell
python figure2_14727250_reproduction\reproduce_figure2_14727250.py `
  --stage plot `
  --output-dir figure2_14727250_reproduction\outputs_full_lr `
  --features figure2_14727250_reproduction\outputs_full_lr\features\pseudo_payload_features.csv `
  --window-size 20 `
  --sequence-width 20 `
  --primary-model logistic_regression
```

## 推荐汇报表述

可以写：

> 本实验借鉴 367 论文 Figure 2 的 Phead/Ptail 遮蔽思想，在 14727250 数据集中选取每次访问的目标 443 连接，并将连接内部按方向变化聚合得到的 pseudo-payload/clump 序列记为 P0/P1/P2。通过比较仅保留前缀片段和删除前缀片段后的分类性能，分析连接内部不同位置对网站指纹识别的贡献。

不建议写：

> 本实验严格复现了 TLS P0/P1/P2 协议阶段。
