"""All fixtures are invented metadata; no test reads an actual audit directory."""
import csv
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from traffic_observer.data import AuditStore, _CsvTail

BASE=dt.datetime(2000,1,1,tzinfo=dt.timezone.utc)
def iso(seconds):return (BASE+dt.timedelta(seconds=seconds)).isoformat()

PHYSICAL=['run_id','sample_id','observed_utc','adapter','interval_start_utc','interval_seconds','rx_delta','tx_delta','counter_status']
SUMMARY=['run_id','sample_id','started_utc','ended_utc','logical_totals']

def write(path,fields,rows):
    with path.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)

def physical(run,sample,end,rx='',status='valid_delta',start=None):
    return {'run_id':run,'sample_id':sample,'observed_utc':iso(end),'adapter':'WLAN_DEMO',
            'interval_start_utc':iso(end-10 if start is None else start),'interval_seconds':10,
            'rx_delta':rx,'tx_delta':0 if rx!='' else '', 'counter_status':status}

def summary(run,sample,end,down=50,valid=True):
    return {'run_id':run,'sample_id':sample,'started_utc':iso(end),'ended_utc':iso(end),
            'logical_totals':json.dumps({'delta_valid':valid,'all_download_delta':down,
                'codex_download_delta':down//2,'unknown_download_delta':down//2,
                'delta_interval_start_utc':iso(end-10),'delta_interval_end_utc':iso(end)})}

class DataTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)

    def test_empty_directory_and_missing_connections_are_unknown(self):
        snap=AuditStore(self.path).snapshot()
        self.assertIsNone(snap['selected_run']);self.assertIsNone(snap['totals']['physical_rx'])
        self.assertTrue(snap['freshness']['stale']);self.assertEqual([],snap['connections'])

    def test_run_isolation_baseline_and_no_cumulative_double_count(self):
        write(self.path/'physical_network.csv',PHYSICAL,[physical('old',1,10,9999),physical('new',1,20,'','baseline'),physical('new',2,30,100)])
        write(self.path/'sample_summary.csv',SUMMARY,[summary('old',1,10,9000),summary('new',1,20,9999,False),summary('new',2,30,50)])
        (self.path/'monitor_state.json').write_text(json.dumps({'run_id':'new','started_utc':iso(20),'last_sample_utc':iso(30),'status':'running','logical_totals':{'all_download_delta':9000000}}))
        snap=AuditStore(self.path).snapshot(minutes=0)
        self.assertEqual('new',snap['selected_run']);self.assertEqual(100,snap['totals']['physical_rx'])
        self.assertEqual(50,snap['totals']['logical_down']);self.assertIsNone(snap['series'][0]['physical_rx_rate'])
        self.assertEqual(9999,AuditStore(self.path).snapshot('old',0)['totals']['physical_rx'])

    def test_incomplete_append_is_deferred_and_incremental_not_duplicated(self):
        f=self.path/'physical_network.csv';write(f,PHYSICAL,[physical('demo',1,10,100)])
        store=AuditStore(self.path);self.assertEqual(100,store.snapshot(minutes=0)['totals']['physical_rx'])
        import io
        buf=io.StringIO(newline='');csv.DictWriter(buf,fieldnames=PHYSICAL).writerow(physical('demo',2,20,200));data=buf.getvalue().encode()
        with f.open('ab') as handle:handle.write(data[:-4])
        self.assertEqual(100,store.snapshot(minutes=0)['totals']['physical_rx'])
        with f.open('ab') as handle:handle.write(data[-4:])
        self.assertEqual(300,store.snapshot(minutes=0)['totals']['physical_rx'])
        self.assertEqual(300,store.snapshot(minutes=0)['totals']['physical_rx'])

    def test_quoted_multiline_record_can_span_polls(self):
        f=self.path/'events.csv';fields=['run_id','sample_id','context_safe']
        write(f,fields,[]);tail=_CsvTail(f);tail.update()
        with f.open('ab') as handle:handle.write(b'demo,1,"one\n')
        tail.update();self.assertEqual(0,len(tail.rows))
        with f.open('ab') as handle:handle.write(b'two"\n')
        tail.update();self.assertEqual('one\ntwo',tail.rows[0]['context_safe'])

    def test_rotation_clears_old_rows_and_counters(self):
        f=self.path/'physical_network.csv';write(f,PHYSICAL,[physical('old',1,10,999)])
        store=AuditStore(self.path);store.snapshot()
        replacement=self.path/'replace.csv';write(replacement,PHYSICAL,[physical('new',1,20,4)])
        replacement.replace(f)
        snap=store.snapshot(minutes=0);self.assertEqual(4,snap['totals']['physical_rx'])
        self.assertEqual(1,snap['coverage']['physical_network.csv']['rotations'])

    def test_reset_and_invalid_logical_delta_remain_gaps(self):
        write(self.path/'physical_network.csv',PHYSICAL,[physical('demo',1,10,100),physical('demo',2,20,-900,'counter_decrease_new_baseline'),physical('demo',3,30,200)])
        write(self.path/'sample_summary.csv',SUMMARY,[summary('demo',1,10,40),summary('demo',2,20,9000,False),summary('demo',3,30,60)])
        snap=AuditStore(self.path).snapshot(minutes=0)
        self.assertEqual(300,snap['totals']['physical_rx']);self.assertEqual(100,snap['totals']['logical_down'])
        self.assertIsNone(snap['series'][1]['physical_rx_rate']);self.assertIsNone(snap['series'][1]['logical_down_rate'])
        self.assertTrue(snap['totals_partial'])
        self.assertEqual(1,snap['measurement_coverage']['physical_gap_rows'])

    def test_window_excludes_crossing_interval_without_proration(self):
        write(self.path/'physical_network.csv',PHYSICAL,[physical('demo',1,10,100),physical('demo',2,20,200),physical('demo',3,30,300)])
        snap=AuditStore(self.path).snapshot(minutes=.25)  # last 15 seconds: complete 20..30 only
        self.assertEqual(300,snap['totals']['physical_rx'])
        self.assertTrue(any('边界' in note for note in snap['limitations']))

    def test_lacking_logical_source_interval_does_not_invent_rate(self):
        row=summary('demo',1,10);o=json.loads(row['logical_totals']);del o['delta_interval_start_utc'];row['logical_totals']=json.dumps(o)
        write(self.path/'sample_summary.csv',SUMMARY,[row]);snap=AuditStore(self.path).snapshot(minutes=0)
        self.assertIsNone(snap['totals']['logical_down']);self.assertIsNone(snap['series'][0]['logical_down_rate'])

    def test_explicit_empty_current_processes_do_not_resurrect_old_pid(self):
        write(self.path/'process_snapshots.csv',['run_id','sample_id','pid','name'],[{'run_id':'demo','sample_id':1,'pid':4242,'name':'codex.exe'}])
        (self.path/'monitor_state.json').write_text(json.dumps({'run_id':'demo','started_utc':iso(0),'last_sample_utc':iso(20),'samples':2,'last_processes':[],'status':'running'}))
        self.assertEqual([],AuditStore(self.path).snapshot()['processes'])

    def test_synthetic_fixture_is_explicit_and_not_reported_live_or_stale(self):
        (self.path/'demo_manifest.json').write_text('{"synthetic":true}')
        write(self.path/'physical_network.csv',PHYSICAL,[physical('demo',1,10,50)])
        snap=AuditStore(self.path).snapshot();self.assertTrue(snap['demo'])
        self.assertEqual('demo',snap['source_status']['monitor']);self.assertFalse(snap['freshness']['stale'])

    def test_bounded_cache_and_tail_report_incomplete_coverage(self):
        f=self.path/'physical_network.csv';write(f,PHYSICAL,[physical('demo',i,i*10,100) for i in range(1,30)])
        tail=_CsvTail(f,max_rows=3,startup_bytes=400);tail.update()
        self.assertLessEqual(len(tail.rows),3);self.assertTrue(tail.truncated)
        self.assertEqual('29',tail.rows[-1]['sample_id'])

    def test_duplicate_rows_do_not_double_count(self):
        row=physical('demo',1,10,100);write(self.path/'physical_network.csv',PHYSICAL,[row,row])
        row2=summary('demo',1,10,40);write(self.path/'sample_summary.csv',SUMMARY,[row2,row2])
        snap=AuditStore(self.path).snapshot(minutes=0)
        self.assertEqual(100,snap['totals']['physical_rx']);self.assertEqual(40,snap['totals']['logical_down'])

    def test_remote_paths_rejected_before_filesystem_access(self):
        for value in ('\\\\example.invalid\\share','https://example.invalid/audit'):
            with self.subTest(path=value),mock.patch.object(Path,'resolve',side_effect=AssertionError('must not resolve remote')):
                with self.assertRaises(ValueError):AuditStore(value)


if __name__=='__main__':unittest.main()
