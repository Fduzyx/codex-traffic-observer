# 数据语义

每一行属于 `run_id` 指定的采集运行段；`sample_id` 只在该运行段内连接不同表。进程身份还需要平台、PID 和进程开始时间，不能跨时间只靠 PID。CSV 为 UTF-8，时间优先使用带时区的 ISO8601 UTC。

| 文件 | 关键字段 | 含义 |
|---|---|---|
| physical_network.csv | observed_utc, interval_start_utc, rx_delta, tx_delta, counter_status | 物理 WLAN 的累计计数差，覆盖所有应用 |
| sample_summary.csv | started_utc, ended_utc, logical_totals | 每次读取的逻辑增量、来源状态及覆盖范围；logical_totals 是 JSON |
| logical_traffic.csv | resolution_ms, bucket_ms, process_class, target_category, outbound_alias, upload_delta_bytes, download_delta_bytes, delta_valid | 监测到的各维度账本增量；累计 upload_bytes/download_bytes 不再次相加 |
| process_snapshots.csv | platform, pid, parent_pid, start_utc, workload, source_observed_utc, is_cached | 进程身份/推断及快照新鲜度，不是字节归属 |
| codex_activity.csv | event_utc, event_type, status, count, confidence | 既有日志中的允许元数据；count 的含义取决于事件类型 |
| live_connections.csv | connection_id, upload_delta, download_delta, counter_status | 只有真实连接来源才有行；缺失不能补造 |
| anomaly_windows.csv | sample_id, physical_intervals, trigger | 人工复核标记；不等于证明异常 |
| monitor_health.csv | source, code, observed_utc | 访问错误、时钟/计数断点或覆盖限制 |
| monitor_state.json | run_id, status, last_sample_utc, samples | 最新运行状态，用于判断停止/过期；不再次加进 CSV 窗口合计 |

首个累计读数是基线，没有可报告的增量。缺失、无效和计数回退不当成零流量。查看器只累计有效增量，分开运行段，并保留缺口提示。时间窗口依据采样时刻筛选，不能把一个跨窗口的测量区间按比例伪造为秒级精度。

Mihomo 的 `resolution=300000` 表示统计桶的分辨率，不代表每个增量恰好发生在桶起点。公开版只读同一种分辨率、比较同一键前后累计值；其它分辨率可能包含同一批数据，禁止相加。逻辑曲线表示记录落库增量的速率，写入延迟可与物理曲线错位。

`codex.exe`、`Unknown`、域名和代理链标签不足以唯一定位工作负载。没有连接身份和逐连接计数时，“最大流量连接”应保持不可用。连接新建、长连接存在、CloseWait 或恢复事件都不能单独证明重复下载。

演示数据通过 `demo_manifest.json` 显式标识为 synthetic。图表选择演示记录自身的时间范围，不把旧演示时间伪装成实时机器数据。

## Unknown 的两种拆分

监测视角以同一运行段、完整来源区间和有效 summary 为依据，再汇总 Unknown 的有效逻辑明细。`resolution_ms=300000` 是唯一允许的分辨率；首基线、无效计数、跨窗区间不能补算。分组由服务、出口以及互斥的同期候选组合构成。进程必须有新鲜、非缓存的来源观测，且创建至观测的已知存活范围与逻辑区间相交。进程未被采到不代表空闲，时间关联不证明它产生了该组字节。

明细和 summary 合计单独对账：缺失部分可以显示为“明细缺失”，不生成服务或进程身份；冲突、过量或读取不完整保留覆盖提示。窗口合计不再加一次状态文件中的累计值。

可选原账本视角是另一项查询：起点向上、终点向下对齐 5 分钟，只选完整半开桶范围。它报告原表内 Unknown 的分组累计量，不是监测器启动后的差分。留存桶覆盖、无记录和读取失败分开显示，不能把它与监测视角相加。公共服务类别仅代表域名标签，匿名来源不是 PID、设备身份或物理出口。
