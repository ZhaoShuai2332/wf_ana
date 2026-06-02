# 14727250 TimeSeries Figure-2-style Result

This run uses the original repository parser path:

`process_pcap() -> FlowSession.temporal_stats_per_flow() -> TimeSeries clumps`

The plot is Figure-2-style, not a numeric reproduction of the paper.
The x-axis labels are protocol-stage-inspired names; without ground-truth protocol-stage annotations, they should be interpreted conservatively.

- parsed visits: 7233
- parse failures: 0
- model: `logistic_regression`
- flow selector: `target-largest`
- sequence width: `20`
- window size: `20`
- critical threshold: `0.02`
- inferred critical window: `P2-P11`

Outputs:

- `features/timeseries_selected_flow_features.csv`
- `metrics/figure2_metrics.csv`
- `metrics/figure2_per_site_f1.csv`
- `metrics/critical_window_summary.csv`
- `plots/figure2_timeseries_clumps.png`
- `plots/figure2_timeseries_clumps.pdf`