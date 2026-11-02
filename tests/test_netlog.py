#!/usr/bin/env python3
"""Unit tests for the pure, curses-free pieces of netlog.

Run with:  python3 -m unittest discover -s tests -v
"""
import contextlib
import io
import sys
import importlib.machinery
import importlib.util
import unittest
from pathlib import Path

# netlog has no .py extension, so load it explicitly by path.
_NETLOG_PATH = Path(__file__).resolve().parent.parent / 'netlog'
_loader = importlib.machinery.SourceFileLoader('netlog', str(_NETLOG_PATH))
_spec = importlib.util.spec_from_loader('netlog', _loader)
netlog = importlib.util.module_from_spec(_spec)
sys.modules['netlog'] = netlog
_loader.exec_module(netlog)


class DedupLinesTest(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(netlog.dedup_lines([]), [])

    def test_no_duplicates(self):
        self.assertEqual(netlog.dedup_lines(['a', 'b', 'c']),
                          [('a', 1), ('b', 1), ('c', 1)])

    def test_consecutive_duplicates_collapsed(self):
        self.assertEqual(netlog.dedup_lines(['a', 'a', 'b', 'b', 'b', 'a']),
                          [('a', 2), ('b', 3), ('a', 1)])

    def test_non_consecutive_duplicates_not_merged(self):
        self.assertEqual(netlog.dedup_lines(['a', 'b', 'a']),
                          [('a', 1), ('b', 1), ('a', 1)])


class StripColsTest(unittest.TestCase):
    def test_zero_columns_is_noop(self):
        self.assertEqual(netlog._strip_cols('a b c', 0), 'a b c')

    def test_strip_one_column(self):
        self.assertEqual(netlog._strip_cols('Jan 1 host: msg', 1), '1 host: msg')

    def test_strip_more_columns_than_exist(self):
        self.assertEqual(netlog._strip_cols('a b', 5), '')

    def test_comma_and_tab_are_delimiters(self):
        self.assertEqual(netlog._strip_cols('a,b\tc', 2), 'c')


class FindMatchesTest(unittest.TestCase):
    def setUp(self):
        self.view = [('hello world', 1), ('foo bar', 1), ('WORLD peace', 1)]

    def test_plain_text_is_case_insensitive(self):
        self.assertEqual(netlog.find_matches(self.view, 'world'), [0, 2])

    def test_regex_mode(self):
        self.assertEqual(netlog.find_matches(self.view, r'^foo', regex=True), [1])

    def test_invalid_regex_yields_no_matches_not_an_exception(self):
        self.assertEqual(netlog.find_matches(self.view, '(', regex=True), [])


class EventTypeTest(unittest.TestCase):
    def test_deny_outranks_error(self):
        result = netlog._event_type('connection denied due to failed auth')
        self.assertEqual(result[0], '✗ ')   # ✗

    def test_allow(self):
        result = netlog._event_type('permit tcp any any')
        self.assertEqual(result[0], '✓ ')   # ✓

    def test_no_match_returns_none(self):
        self.assertIsNone(netlog._event_type('just some ordinary log text'))


class FileBaseTest(unittest.TestCase):
    def test_strips_from_first_dot(self):
        self.assertEqual(netlog._file_base('firewall.log.10.gz'), 'firewall')

    def test_no_dot_returns_whole_name(self):
        self.assertEqual(netlog._file_base('syslog'), 'syslog')

    def test_uses_basename_not_full_path(self):
        self.assertEqual(netlog._file_base('/var/log/firewall.log'), 'firewall')


class CollectSegmentsTest(unittest.TestCase):
    def setUp(self):
        self.vendors = {}
        self.mac_map = {}
        self.ctr = [0]

    def test_no_two_segments_overlap(self):
        line = '00:11:22:33:44:55 talked to 10.0.0.1 on port 443'
        segs = netlog._collect_segments(line, self.vendors, self.mac_map, self.ctr)
        spans = [(s, e) for s, e, *_ in segs]
        for i, (s1, e1) in enumerate(spans):
            for s2, e2 in spans[i + 1:]:
                self.assertFalse(s1 < e2 and s2 < e1, f'{spans[i]} overlaps {(s2, e2)}')

    def test_well_known_port_name_shown(self):
        segs = netlog._collect_segments('dport=443', self.vendors, self.mac_map, self.ctr)
        disp = [d for _, _, d, *_ in segs]
        self.assertTrue(any('HTTPS' in d for d in disp))

    def test_search_term_does_not_duplicate_higher_priority_match(self):
        segs = netlog._collect_segments('10.0.0.1 error', self.vendors, self.mac_map,
                                         self.ctr, search_term='10.0.0.1')
        ip_hits = [s for s in segs if s[2] == '10.0.0.1']
        self.assertEqual(len(ip_hits), 1)


class ParseArgsTest(unittest.TestCase):
    def test_plain_file(self):
        follow, n, files, alert, egrep, setup = netlog.parse_args(['somefile.log'])
        self.assertFalse(follow)
        self.assertEqual(n, 10)
        self.assertEqual(files, [Path('somefile.log')])
        self.assertIsNone(alert)
        self.assertIsNone(egrep)
        self.assertFalse(setup)

    def test_follow_with_egrep_pattern_and_tail_count(self):
        follow, n, files, alert, egrep, setup = netlog.parse_args(
            ['-f', '-n', '50', 'deny|drop', 'firewall.log'])
        self.assertTrue(follow)
        self.assertEqual(n, 50)
        self.assertEqual(egrep, 'deny|drop')
        self.assertEqual(files, [Path('firewall.log')])

    def test_follow_single_file_has_no_egrep_pattern(self):
        follow, n, files, alert, egrep, setup = netlog.parse_args(['-f', 'firewall.log'])
        self.assertIsNone(egrep)
        self.assertEqual(files, [Path('firewall.log')])

    def test_alert_flag(self):
        *_, alert, egrep, setup = netlog.parse_args(['-f', '--alert', 'DENY', 'x.log'])
        self.assertEqual(alert, 'DENY')

    def test_setup_geoip_flag(self):
        *_, setup = netlog.parse_args(['--setup-geoip'])
        self.assertTrue(setup)

    def test_bad_n_value_raises_cleanly(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            netlog.parse_args(['-n', 'not-a-number', 'x.log'])


if __name__ == '__main__':
    unittest.main()
