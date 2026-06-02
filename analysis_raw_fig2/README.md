# Raw-PCAP Figure-2-style Head/Tail Ablation

本模块对 **raw pcap** 执行 flow/clump-level 的 head/tail ablation，用于模拟论文 *Understanding and Explaining Web Fingerprinting with a Protocol-Centric Approach* 中 Figure 2 的分析思想。

本分析定位的是 **加密流量元信息中的统计泄露位置**，不是明文协议语义或内容语义。不能把 clump 直接解释为明文 HTTP request/response，也不能把高准确率解释为模型理解了网页、视频或应用内容。

## 输入边界

本脚本只接受 raw `.pcap` / `.pcapng`：

```bash
python -m analysis_raw_fig2.run_raw_fig2_ablation --manifest manifest.csv
```

如果输入的是 `features_H123/result_*.csv` 这类 processed H123 feature CSV，程序会报错：

```text
This script expects raw pcap files for protocol-level Figure-2-style analysis. Processed H123 features should use a separate feature-position ablation script.
```

这不是 feature-position ablation 主结果；H123 processed feature 的位置消融应放在单独脚本中。

## 与 Figure 2 的关系

原论文 Figure 2 比较 flow 内前缀保留和前缀删除后的分类性能。本实现使用仓库已有 PCAP 解析链路：

```text
raw pcap + metadata
  -> process_pcap()
  -> FlowSession.temporal_stats_per_flow()
  -> visit-level multi-flow tensor [M, K, F]
  -> Fhead(k) / Ftail(k)
  -> train/evaluate classifier
  -> metrics and plots
```

本实现接近 Figure 2 的 Fhead/Ftail 思想，但不保证复现论文原始 Figure 2 的数值。差异来源包括数据集、标签空间、模型、flow/message/clump 定义和采集环境。

## Clump 与默认特征

默认使用 `TimeSeries(buffer_tcp=True)` 的 clump 定义：连续同方向 TLS/QUIC 包被聚合为一个 temporal event / clump。

默认模型输入只包含：

```text
relative_timestamp, duration, length, pkt_count, direction
```

DNS、SNI、domain、IP、URL 不进入默认模型输入。URL 默认也不会写入输出 CSV；如确需调试，可显式使用 `--allow-sensitive-metadata-output`。

## Visit-level 表征

分类样本是 visit，不是 flow。若一个 visit 内有多个 flow，会构造成：

```text
X_visit: [M, K, F]
```

其中 `M` 是保留的 flow 数，`K` 是每条 flow 的 clump/event 数，`F` 是 clump 特征数。传统 ML baseline 会 flatten 为 `[M * K * F]`。

默认参数：

```text
--top-m-flows 8
--max-events 64
--flow-rank-by bytes_total
--feature-set default
```

## Fhead / Ftail 语义

`Fhead(k)`：每条 flow 只保留前 `k` 个 clump，后续位置置零。

`Ftail(k)`：每条 flow 删除或遮蔽前 `k` 个 clump。默认是不左移，只把前缀置零并保持事件位置语义。

可选：

```bash
--tail-shift-left
```

开启后，删除前 `k` 个 clump 后把剩余 clump 左移到开头。默认关闭，因为不左移更适合分析“位置”贡献。

边界：

- `k <= 0`：报错。
- `k > K`：`Fhead(k)` 等价 full；`Ftail(k)` 等价全零输入，并写 warning。
- full baseline 记录为 `ablation_type=full, k=-1`。

## 数据划分与防泄漏

如果 manifest 有 `split_group` 列，则使用：

```text
split_group == train
split_group == test
```

如果没有 `split_group`，按 label 做 stratified train/test split。

同一个 `visit_id` 不允许同时出现在 train 和 test。可额外指定：

```bash
--group-split-by content_id
--group-split-by url
```

指定 `url` 时输出中默认只保留 `url_sha256`。

## 运行示例

Manifest 输入：

```bash
python -m analysis_raw_fig2.run_raw_fig2_ablation \
  --manifest /data/h123_raw/manifest.csv \
  --out-dir outputs/raw_fig2_platform \
  --label-col label \
  --top-m-flows 8 \
  --max-events 64 \
  --flow-rank-by bytes_total \
  --model random_forest \
  --k-list 1 2 3 4 5 8 16 32 64 \
  --seeds 0 1 2 3 4 \
  --test-size 0.25 \
  --scaler standard \
  --log-transform length pkt_count duration relative_timestamp
```

目录扫描：

```bash
python -m analysis_raw_fig2.run_raw_fig2_ablation \
  --pcap-dir /data/h123_raw/pcaps \
  --label-from parent_dir \
  --out-dir outputs/raw_fig2_dirscan \
  --top-m-flows 8 \
  --max-events 64 \
  --model logistic_regression \
  --k-list 1 2 3 4 5 8 16 32 \
  --seeds 0 1 2 \
  --num-workers 0
```

`--num-workers 0` 会自动选择一个保守的并行度，默认最多 4 个 TShark 解析进程。若机器内存充足，可手动设置 `--num-workers 4` 或 `--num-workers 8`；若需要排查单个 PCAP 解析问题，可设置 `--num-workers 1` 串行运行。

使用缓存：

```bash
python -m analysis_raw_fig2.run_raw_fig2_ablation \
  --manifest /data/h123_raw/manifest.csv \
  --out-dir outputs/raw_fig2_cached \
  --use-cache \
  --model random_forest \
  --k-list 1 2 3 4 5 8 16 32 64
```

## 输出文件

默认输出到 `--out-dir`：

- `config.json`：命令行参数、UTC 时间戳、git commit hash（若可获得）。
- `dataset_summary.json`：visit/class/flow/event 统计。
- `results_long.csv`：每个 seed、k、ablation type、metric 的长表。
- `results_summary.csv`：按 ablation type、k、model、metric 聚合的均值/标准差。
- `confusion_matrices/confusion_seed_0_full.csv` 等混淆矩阵。
- `cache/visit_tensors.npz` 与 `cache/visit_metadata.csv`。
- `errors.csv`：PCAP 解析失败记录。
- `logs/run.log` 与 `logs/warnings.log`。
- `plots/fhead_ftail_accuracy.png/.pdf`。
- `plots/fhead_ftail_macro_f1.png/.pdf`。

## 曲线解释

- `Fhead(k)` 上升快：前部 clump 有较强区分性。
- `Ftail(k)` 随 `k` 增大下降快：被遮蔽的前部 clump 重要。
- `Ftail(k)` 仍保持高性能：后部 clump 也包含冗余或互补信息。
- `full baseline` 是完整 flow/clump 元信息下的参考上界。

这些结论只支持“加密流量元信息存在统计侧信道”这一层面的解释。若没有协议阶段标注，不能声称某个 `k` 精确对应 TLS handshake、HTTP request 或 HTTP response。

## 常见问题

`process_pcap import failed`：请安装 `crawlers` 包，或设置：

```bash
export PYTHONPATH=/path/to/repo/crawlers/src:$PYTHONPATH
```

Windows PowerShell：

```powershell
$env:PYTHONPATH="D:\projects\wf-ana\crawlers\src;$env:PYTHONPATH"
```

`pyshark/tshark` 失败：确认已安装 Wireshark/TShark，并且 `tshark` 在 PATH 中。

`pcap produced no valid flow temporal data`：该 pcap 中可能没有 TLS/QUIC，或 flow 因丢包/异常被原解析逻辑跳过。
