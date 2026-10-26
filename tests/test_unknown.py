"""Invented Unknown metadata only; no original audit or business files are read."""
import csv
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from traffic_observer.data import AuditStore
from traffic_observer.unknown import build_unknown_breakdown

BASE = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)


def iso(seconds):
    return (BASE + dt.timedelta(seconds=seconds)).isoformat()


def stamp(seconds):
    return (BASE + dt.timedelta(seconds=seconds)).timestamp()


def summary(sample=1, end=10, down=100, up=20, **changes):
    logical = {"delta_valid":True, "resolution_ms":300000,
        "delta_interval_start_utc":iso(end-10), "delta_interval_end_utc":iso(end),
        "unknown_download_delta":down, "process_deltas":{"Unknown":{"upload_delta":up}}}
    logical.update(changes)
    return {"run_id":"demo", "sample_id":str(sample), "started_utc":iso(end-2),
        "ended_utc":iso(end+1), "logical_totals":json.dumps(logical)}


def detail(sample=1, down=100, up=20, **changes):
    row = {"run_id":"demo", "sample_id":str(sample), "observed_utc":iso(sample*10),
        "resolution_ms":"300000", "bucket_ms":str(int(stamp(0)*1000)),
        "process_class":"Unknown", "target_category":"chatgpt_exact",
        "outbound_alias":"DIRECT", "upload_bytes":"9999999999", "download_bytes":"9999999999",
        "upload_delta_bytes":str(up), "download_delta_bytes":str(down), "samples_delta":"1",
        "delta_status":"DELTA", "delta_valid":"True", "closed_bucket_write":"False",
        "pre_observation_bucket":"False"}
    row.update(changes)
    return row


def process(sample=1, pid=7000, workload="CodexDesktop", **changes):
    row = {"run_id":"demo", "sample_id":str(sample), "pid":str(pid), "platform":"windows",
        "workload":workload, "exe_category":"codex_desktop_engine_path",
        "confidence":"synthetic_demo_only", "is_cached":"False", "start_utc":iso(-60),
        "source_observed_utc":iso(sample*10), "observed_utc":iso(sample*10)}
    row.update(changes)
    return row


def coverage():
    return {name:{"status":"readable", "retained_rows":1} for name in (
        "sample_summary.csv", "logical_traffic.csv", "process_snapshots.csv")}


def build(summaries=None, details=None, processes=None, **kwargs):
    return build_unknown_breakdown([summary()] if summaries is None else summaries,
        [detail()] if details is None else details, [process()] if processes is None else processes,
        start=kwargs.pop("start", None), end=kwargs.pop("end", stamp(100)),
        source_coverage=kwargs.pop("source_coverage", coverage()), **kwargs)


class UnknownTests(unittest.TestCase):
    def test_two_workloads_are_one_mutually_exclusive_group_not_two_totals(self):
        result = build(processes=[process(), process(pid=7100, workload="CampusMainWSL", platform="wsl")])
        self.assertEqual(100, result["total_down"])
        self.assertEqual(100, sum(r["download_bytes"] for r in result["groups"]))
        self.assertEqual(1, len(result["groups"]))
        group = result["groups"][0]
        self.assertEqual("CampusRadarWSL+CodexDesktop", group["workload_key"])
        self.assertEqual({7000,7100}, {c["pid"] for c in group["candidates"]})
        self.assertEqual("coobserved_only", group["evidence_level"])
        self.assertEqual(1, group["download_share"])

    def test_summary_window_boundaries_apply_to_details_without_proration(self):
        result = build([summary(1,10),summary(2,20),summary(3,30)],
            [detail(1),detail(2),detail(3)], start=stamp(15), end=stamp(30))
        self.assertEqual(100, result["total_down"])
        self.assertEqual(100, result["detail_down"])
        self.assertEqual(1, result["coverage"]["summary_samples"])
        self.assertEqual(3, result["groups"][0]["first_sample_id"])

    def test_stale_cached_or_nonoverlapping_process_is_missing_not_idle(self):
        for changes in ({"is_cached":"True"}, {"source_observed_utc":iso(7)},
                        {"start_utc":iso(10)}, {"is_cached":""},
                        {"is_cached":"False", "cache_age_seconds":"0.1"}):
            with self.subTest(changes=changes):
                result = build(processes=[process(**changes)])
                group = result["groups"][0]
                self.assertEqual("process_observation_missing", group["workload_key"])
                self.assertEqual([], group["candidates"])
                self.assertGreater(result["coverage"]["stale_or_invalid_process_rows"], 0)
        result = build(processes=[process(),process(pid=7100,workload="CampusMainWSL",is_cached="True")])
        self.assertEqual("CodexDesktop", result["groups"][0]["workload_key"])
        self.assertIn("非独占", result["groups"][0]["workload_label"])
        self.assertFalse(result["coverage"]["process_observations_complete"])

    def test_verified_probe_categories_and_parent_pid_are_retained(self):
        result = build(processes=[process(parent_pid="6990", exe_category="codex_other_wsl_runtime",
            confidence="high_ancestor_path", cache_age_seconds="0")])
        candidate = result["groups"][0]["candidates"][0]
        self.assertEqual(6990, candidate["parent_pid"])
        self.assertEqual("codex_other_wsl_runtime", candidate["exe_category"])
        self.assertEqual("high_ancestor_path", candidate["confidence"])

    def test_independent_database_view_keeps_its_totals_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            row=summary()
            with (path/"sample_summary.csv").open("w",encoding="utf-8",newline="") as f:
                writer=csv.DictWriter(f,fieldnames=list(row));writer.writeheader();writer.writerow(row)
            with mock.patch("traffic_observer.ledger_details.UnknownLedgerDetails") as factory:
                factory.return_value.snapshot.return_value={"status":"ok", "total_down":999999,
                    "total_up":500, "rows":[]}
                store=AuditStore(path,mihomo_db=path/"fictional.db")
                result=store.snapshot("demo",0)
                factory.assert_called_once_with(path/"fictional.db")
                factory.return_value.snapshot.assert_called_once_with(iso(0),iso(11))
                self.assertEqual(100,result["totals"]["unknown_down"])
                self.assertEqual(100,result["unknown_breakdown"]["total_down"])
                self.assertEqual(999999,result["unknown_ledger_details"]["total_down"])

    def test_reset_baseline_and_multiple_resolutions_are_never_summed(self):
        result = build(details=[detail(down=999999,delta_status="COUNTER_DECREASE"),
            detail(down=999999,resolution_ms="3600000")])
        self.assertEqual(0, result["detail_down"])
        self.assertEqual(100, result["residual_down"])
        self.assertEqual(1, result["coverage"]["invalid_rows"])
        self.assertEqual(1, result["coverage"]["unsupported_resolution_rows"])
        result = build(summaries=[summary(counter_discontinuity=True)])
        self.assertIsNone(result["total_down"])
        self.assertEqual([], result["groups"])

    def test_identical_duplicate_key_ignored_and_conflict_excluded(self):
        result = build(details=[detail(),detail()])
        self.assertEqual(100, result["detail_down"])
        self.assertEqual(1, result["coverage"]["duplicate_rows"])
        result = build(details=[detail(),detail(down=101)])
        self.assertEqual(0, result["detail_down"])
        self.assertEqual(1, result["coverage"]["conflicting_rows"])
        self.assertFalse(result["coverage"]["complete"])

    def test_other_service_and_named_route_never_echo_raw_metadata(self):
        secret = "private-name.example.invalid/account/placeholder"
        result = build(details=[detail(target_category=secret,outbound_alias=secret,service=secret)],
            processes=[process(workload=secret,exe_category=secret,confidence=secret,platform=secret)])
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual("other", result["groups"][0]["service_category"])
        self.assertTrue(result["groups"][0]["route_alias"].startswith("route_"))

    def test_partial_missing_tail_and_overshoot_are_honest(self):
        sources = coverage(); sources["logical_traffic.csv"]["tail_truncated"] = True
        result = build(details=[detail(down=60,up=12)],source_coverage=sources)
        self.assertEqual(40,result["residual_down"]); self.assertEqual(8,result["residual_up"])
        self.assertEqual(.6,result["groups"][0]["download_share"])
        self.assertFalse(result["coverage"]["complete"])
        result = build(details=[detail(down=101)])
        self.assertEqual(0,result["detail_down"])
        self.assertEqual(100,result["residual_down"])
        self.assertEqual(1,result["coverage"]["overshoot_samples"])
        result = build(details=[], source_coverage={})
        self.assertEqual("partial", result["status"])
        self.assertEqual(100, result["residual_down"])

    def test_missing_summary_up_is_unknown_not_detail_sum(self):
        result = build(summaries=[summary(up=None)])
        self.assertIsNone(result["total_up"])
        self.assertIsNone(result["residual_up"])
        self.assertEqual(20,result["detail_up"])

    def test_late_writes_and_distinct_service_route_partition_once(self):
        result = build(details=[detail(down=60,up=10,closed_bucket_write="True"),
            detail(down=40,up=10,target_category="chatgpt_subdomain",outbound_alias="node_abcdef012345",
                   pre_observation_bucket="True")])
        self.assertEqual(2,len(result["groups"]))
        self.assertEqual(100,sum(g["download_bytes"] for g in result["groups"]))
        self.assertEqual(1,result["coverage"]["closed_bucket_write_rows"])
        self.assertEqual(1,result["coverage"]["pre_observation_bucket_rows"])
        self.assertEqual(0,result["residual_down"])

    def test_loader_isolates_run_and_does_not_open_database_by_default_or_in_demo(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            rows = [summary()]; old = summary(down=999999); old["run_id"]="old"; rows.append(old)
            for name, records in (("sample_summary.csv",rows),("logical_traffic.csv",[detail()]),
                                  ("process_snapshots.csv",[process()])):
                with (path/name).open("w",encoding="utf-8",newline="") as f:
                    writer=csv.DictWriter(f,fieldnames=list(records[0]));writer.writeheader();writer.writerows(records)
            store = AuditStore(path)
            result=store.snapshot("demo",0)
            self.assertEqual(100,result["unknown_breakdown"]["detail_down"])
            self.assertEqual(result["totals"]["unknown_down"],result["unknown_breakdown"]["total_down"])
            self.assertEqual("not_configured",result["unknown_ledger_details"]["status"])
            self.assertIsNone(store._ledger_details)
            (path/"demo_manifest.json").write_text('{"synthetic":true}',encoding="utf-8")
            store=AuditStore(path,mihomo_db="this-must-never-be-opened")
            result=store.snapshot("demo",0)
            self.assertIsNone(store._ledger_details)
            self.assertEqual("synthetic_demo_ignores_external_database",result["unknown_ledger_details"]["reason"])


if __name__ == "__main__":
    unittest.main()
