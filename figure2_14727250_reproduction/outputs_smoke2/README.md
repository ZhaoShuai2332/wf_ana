# 14727250 Figure 2 风格复现实验

## 实验定位

本目录用于在 14727250 数据集上复现 367 论文 Figure 2 的核心方法，即通过 Phead(i) / Ptail(i) 遮蔽实验观察连接内部不同位置对网站指纹分类的贡献。

由于 14727250 与原论文数据集不同，本文中的 P_i 被定义为目标 443 连接内按方向变化聚合得到的 pseudo-payload/clump。该定义尽量贴近原仓库 `TimeSeries._clumps()` 中的方向聚合思想，但不声称每个 P_i 都严格对应 TLS 协议阶段。

## 输出文件

- `features/pseudo_payload_features.csv`：每个访问样本抽取出的 P-like 序列。
- `features/site_coverage.csv`：各站点样本数与是否纳入评估。
- `features/extraction_failures.csv`：PCAP 解析或目标连接选择失败记录。
- `metrics/model_metrics.csv`：完整 P 序列下不同模型的分类指标。
- `metrics/figure2_metrics.csv`：Phead/Ptail 每个位置的 macro-F1、weighted-F1 等指标。
- `metrics/figure2_per_site_f1.csv`：绘制小提琴图使用的 per-site F1 分布。
- `metrics/position_stage_summary.csv`：每个 P 位置的统计特征与保守阶段解释。
- `plots/figure2_pseudo_payload_positions.png`：最终 Figure 2 风格复现图。

## 当前结果摘要

完整序列模型结果：

| model | status | evaluation_mode | split_strategy | accuracy | f1_macro | f1_weighted | n_splits | reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| logistic_regression | completed | multiclass | StratifiedGroupKFold | 0.7708333333333334 | 0.7576381951381952 | 0.7576381951381951 | 3 |  |

关键窗口结果：

| full_f1_macro | threshold_drop | threshold_f1_macro | critical_start_position | critical_end_position | critical_window |
| --- | --- | --- | --- | --- | --- |
| 0.7576381951381952 | 0.02 | 0.7376381951381952 | 1 | 1 | P1-P1 |

P 位置阶段解释摘要：

| label | coverage_pct | length_median | direction_median | stage_interpretation |
| --- | --- | --- | --- | --- |
| P0 | 100.0 | 1870.5 | 1.0 | 连接内首个可见载荷片段，通常可对应客户端初始发送阶段；若为 TLS/TCP，可能包含 ClientHello 或早期加密前载荷。 |
| P1 | 100.0 | 5405.5 | -1.0 | 连接内首个反向响应片段，通常可对应服务器早期响应阶段；若为 TLS/TCP，可能覆盖 ServerHello/服务器首轮响应。 |
| P2 | 100.0 | 608.0 | 1.0 | 早期交互片段，主要方向为客户端侧，常用于刻画握手后首轮请求/响应或 QUIC 早期数据。 |
| P3 | 100.0 | 397.5 | -1.0 | 早期交互片段，主要方向为服务端侧，常用于刻画握手后首轮请求/响应或 QUIC 早期数据。 |
| P4 | 97.91666666666666 | 105.0 | 1.0 | 连接早期数据交换阶段，主要方向为客户端侧，可能包含首批应用数据或大对象返回。 |
| P5 | 95.83333333333334 | 1161.0 | -1.0 | 连接早期数据交换阶段，主要方向为服务端侧，可能包含首批应用数据或大对象返回。 |
| P6 | 83.33333333333334 | 398.5 | 1.0 | 连接早期数据交换阶段，主要方向为客户端侧，可能包含首批应用数据或大对象返回。 |
| P7 | 83.33333333333334 | 6332.5 | -1.0 | 连接早期数据交换阶段，主要方向为服务端侧，可能包含首批应用数据或大对象返回。 |

图像文件：`figure2_14727250_reproduction\outputs_smoke2\plots\figure2_pseudo_payload_positions.png`

## 方法边界

该复现实验可用于支持“14727250 数据集上目标连接内部 pseudo-payload 位置贡献分析”这一表述。若要声称严格 TLS P0/P1/P2 阶段复现，还需要进一步进行 TLS record 重组、ClientHello/ServerHello/EncryptedExtensions 等消息级解析，并处理 TLS 1.3 加密握手内容不可见的问题。
