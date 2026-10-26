"""Physical WLAN counters, with explicit baselines and counter discontinuities."""
from __future__ import annotations

import datetime as dt
from .common import local_powershell

QUERY = r'''
$rows=@(Get-NetAdapter -Physical | Where-Object {"$($_.PhysicalMediaType)" -match '802.11'} | ForEach-Object {
  $a=$_; $s=$a | Get-NetAdapterStatistics
  [pscustomobject]@{adapter_key=[string]$a.InterfaceGuid;if_index=[int]$a.ifIndex;status=[string]$a.Status;
    received_bytes=[long]$s.ReceivedBytes;sent_bytes=[long]$s.SentBytes;observed_utc=[DateTime]::UtcNow.ToString('o')}
}); ConvertTo-Json -InputObject $rows -Compress
'''


def seconds(value: str) -> float:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


class PhysicalProbe:
    def __init__(self):
        self.previous: dict[str, dict] = {}
        self.aliases: dict[str, str] = {}

    def poll(self, sample_id: int, observed_utc: str) -> dict:
        rows, health = [], []
        try:
            snapshot = local_powershell(QUERY)
        except Exception:
            return {"rows": [], "health": ["PHYSICAL_WLAN_READ_UNAVAILABLE"]}
        seen = set()
        for value in snapshot:
            key = str(value["adapter_key"])
            seen.add(key)
            self.aliases.setdefault(key, "WLAN_" + str(len(self.aliases) + 1))
            previous = self.previous.get(key)
            rx = tx = elapsed = None
            status = "baseline"
            if previous is not None:
                elapsed = seconds(value["observed_utc"]) - seconds(previous["observed_utc"])
                if min(value["received_bytes"] - previous["received_bytes"], value["sent_bytes"] - previous["sent_bytes"]) < 0:
                    status = "counter_decrease_new_baseline"
                elif elapsed <= 0:
                    status = "clock_discontinuity_new_baseline"
                else:
                    rx = value["received_bytes"] - previous["received_bytes"]
                    tx = value["sent_bytes"] - previous["sent_bytes"]
                    status = "valid_delta"
                if status != "valid_delta":
                    health.append(status)
            rows.append({
                "sample_id": sample_id, "observed_utc": value["observed_utc"],
                "adapter": self.aliases[key], "if_index": value["if_index"], "link_status": value["status"],
                "received_bytes": value["received_bytes"], "sent_bytes": value["sent_bytes"],
                "interval_start_utc": previous["observed_utc"] if previous else None,
                "interval_seconds": elapsed, "rx_delta": rx, "tx_delta": tx,
                "rx_bytes_per_second": rx / elapsed if rx is not None else None,
                "tx_bytes_per_second": tx / elapsed if tx is not None else None,
                "counter_status": status,
            })
            self.previous[key] = value
        for key in set(self.previous) - seen:
            del self.previous[key]
            health.append("PHYSICAL_ADAPTER_DISAPPEARED")
        if not snapshot:
            health.append("NO_PHYSICAL_WLAN_ADAPTER")
        return {"rows": rows, "health": health}
