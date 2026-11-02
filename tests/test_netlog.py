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
        self.assertIsNone(netlog.parse_event('dnsmasq[7]: query[A] example.com from 10.0.0.5'))

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
                        'Access points by failure rate', 'Failure loops', 'Identity inconsistencies'):
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


class AnalysisCliTest(unittest.TestCase):
    def test_analysis_options(self):
        ns = netlog.parse_cli(['--summary', '--client', 'alice', '--loop-window', '5m',
                               '--loop-threshold', '4', 'x.log'])
        self.assertTrue(ns.summary)
        self.assertEqual(ns.client, 'alice')
        self.assertEqual(ns.loop_window, 300)
        self.assertEqual(ns.loop_threshold, 4)
        self.assertEqual(ns.log_files, [Path('x.log')])

    def test_formats_flag(self):
        self.assertTrue(netlog.parse_cli(['--formats']).formats)

    def test_bad_values_rejected(self):
        for argv in (['-f', '--summary', 'x.log'], ['--legacy-ssid', '(', 'x.log'],
                     ['--loop-window', 'soon', 'x.log'], ['--loop-threshold', '0', 'x.log']):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                netlog.parse_cli(argv)


if __name__ == '__main__':
    unittest.main()
