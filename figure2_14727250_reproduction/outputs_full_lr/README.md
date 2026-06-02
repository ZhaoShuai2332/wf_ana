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
| logistic_regression | completed | multiclass | StratifiedGroupKFold | 0.8158440481128163 | 0.8076848633836351 | 0.8131268412542878 | 5 |  |

关键窗口结果：

| full_f1_macro | threshold_drop | threshold_f1_macro | critical_start_position | critical_end_position | critical_window |
| --- | --- | --- | --- | --- | --- |
| 0.8076848633836351 | 0.02 | 0.7876848633836351 | 1 | 11 | P1-P11 |

P 位置阶段解释摘要：

| label | paper_stage | coverage_pct | length_median | direction_median | stage_interpretation |
| --- | --- | --- | --- | --- | --- |
| P0 | Client Hello | 100.0 | 1788.0 | 1.0 | Client Hello 阶段：连接内第一个客户端侧可见载荷片段，通常对应 TLS ClientHello 或 QUIC Initial 中的客户端初始握手信息。 |
| P1 | Server Hello | 100.0 | 4288.0 | -1.0 | Server Hello 阶段：连接内第一个服务端侧可见载荷片段，通常对应 TLS ServerHello/服务器早期握手响应或 QUIC Initial 响应。 |
| P2 | Client Req. | 100.0 | 613.0 | 1.0 | Client Req. 阶段：握手后的首个客户端请求或客户端应用数据片段，近似对应原论文中的第一次客户端请求。 |
| P3 | Server Resp. | 100.0 | 635.0 | -1.0 | Server Resp. 阶段：握手后的首个服务端响应或服务端应用数据片段，近似对应原论文中的第一次服务器响应。 |
| P4 | Client Req. | 98.56214572100096 | 38.0 | 1.0 | 后续 Client Req. 阶段：连接内第 2 轮客户端侧请求/上行数据片段；当前统计中主要方向为客户端侧。 |
| P5 | Server Resp. | 98.50684363334716 | 3216.0 | -1.0 | 后续 Server Resp. 阶段：连接内第 2 轮服务端侧响应/下行数据片段；当前统计中主要方向为服务端侧。 |
| P6 | Client Req. | 91.45582745748652 | 412.0 | 1.0 | 后续 Client Req. 阶段：连接内第 3 轮客户端侧请求/上行数据片段；当前统计中主要方向为客户端侧。 |
| P7 | Server Resp. | 89.74146274021845 | 25095.0 | -1.0 | 后续 Server Resp. 阶段：服务端侧较大响应片段，可能对应资源内容返回或批量数据传输。 |
| P8 | Client Req. | 80.29863127333057 | 344.0 | 1.0 | 后续 Client Req. 阶段：连接内第 4 轮客户端侧请求/上行数据片段；当前统计中主要方向为客户端侧。 |
| P9 | Server Resp. | 78.47366238075487 | 23597.0 | -1.0 | 后续 Server Resp. 阶段：服务端侧较大响应片段，可能对应资源内容返回或批量数据传输。 |
| P10 | Client Req. | 70.92492741600995 | 284.0 | 1.0 | 后续 Client Req. 阶段：连接内第 5 轮客户端侧请求/上行数据片段；当前统计中主要方向为客户端侧。 |
| P11 | Server Resp. | 69.70828148762615 | 19521.0 | -1.0 | 后续 Server Resp. 阶段：连接内第 5 轮服务端侧响应/下行数据片段；当前统计中主要方向为服务端侧。 |
| P12 | Client Req. | 63.25176275404396 | 257.0 | 1.0 | 后续 Client Req. 阶段：连接内第 6 轮客户端侧请求/上行数据片段；当前统计中主要方向为客户端侧。 |
| P13 | Server Resp. | 62.89229918429421 | 16406.0 | -1.0 | 后续 Server Resp. 阶段：连接内第 6 轮服务端侧响应/下行数据片段；当前统计中主要方向为服务端侧。 |
| P14 | Client Req. | 58.39900456242223 | 258.0 | 1.0 | 后续 Client Req. 阶段：连接内第 7 轮客户端侧请求/上行数据片段；当前统计中主要方向为客户端侧。 |
| P15 | Server Resp. | 58.13631964606664 | 12802.0 | -1.0 | 后续 Server Resp. 阶段：连接内第 7 轮服务端侧响应/下行数据片段；当前统计中主要方向为服务端侧。 |
| P16 | Client Req. | 53.5185953269736 | 258.0 | 1.0 | 后续 Client Req. 阶段：连接内第 8 轮客户端侧请求/上行数据片段；当前统计中主要方向为客户端侧。 |
| P17 | Server Resp. | 53.39416562975252 | 11503.5 | -1.0 | 后续 Server Resp. 阶段：连接内第 8 轮服务端侧响应/下行数据片段；当前统计中主要方向为服务端侧。 |
| P18 | Client Req. | 49.53684501589935 | 237.0 | 1.0 | 后续 Client Req. 阶段：仅部分样本存在的客户端侧后续请求片段，更多反映长连接或多轮请求差异。 |
| P19 | Server Resp. | 49.37093875293792 | 10491.0 | -1.0 | 后续 Server Resp. 阶段：仅部分样本存在的服务端侧后续响应片段，更多反映连接尾部或长连接差异。 |

图像文件：`figure2_14727250_reproduction\outputs_full_lr\plots\figure2_pseudo_payload_positions.png`

## 方法边界

该复现实验可用于支持“14727250 数据集上目标连接内部 pseudo-payload 位置贡献分析”这一表述。若要声称严格 TLS P0/P1/P2 阶段复现，还需要进一步进行 TLS record 重组、ClientHello/ServerHello/EncryptedExtensions 等消息级解析，并处理 TLS 1.3 加密握手内容不可见的问题。
