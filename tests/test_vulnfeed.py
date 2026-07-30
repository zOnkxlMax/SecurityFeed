"""Testsuite fuer vulnfeed.py - laeuft ohne Netzwerk und ohne Fremdpakete.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import signal
import socket
import sys
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vulnfeed as vf  # noqa: E402


RSS_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <title>Example Security</title>
    <item>
      <title>vBulletin fixes critical pre-auth RCE flaw</title>
      <link>https://example.test/vbulletin-rce/</link>
      <pubDate>Tue, 28 Jul 2026 17:17:39 -0400</pubDate>
      <category><![CDATA[Security]]></category>
      <description><![CDATA[<p>A critical vulnerability &amp; more.</p>]]></description>
    </item>
    <item>
      <title>Weekly newsletter roundup</title>
      <link>https://example.test/newsletter/</link>
      <pubDate>Mon, 27 Jul 2026 10:00:00 +0000</pubDate>
      <description>Nothing special this week.</description>
    </item>
  </channel>
</rss>
"""

ATOM_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>heise Security Alerts</title>
  <entry>
    <title type="html"><![CDATA[Attacken auf Progress LoadMaster moeglich]]></title>
    <id>urn:bid:5125105</id>
    <link href="https://example.test/loadmaster"/>
    <updated>2026-07-28T12:15:00.000Z</updated>
    <summary type="html"><![CDATA[LoadMaster ist verwundbar, CVE-2026-59686 behoben.]]></summary>
    <published>2026-07-28T12:15:00.000Z</published>
  </entry>
</feed>
"""


def entry(**kwargs) -> vf.Entry:
    """Entry mit sinnvollen Vorgaben, damit Tests nur Relevantes setzen."""
    defaults = dict(
        source="Testquelle",
        title="Irgendein Titel",
        link="https://example.test/a",
        published=datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc),
        summary="",
    )
    defaults.update(kwargs)
    return vf.Entry(**defaults)


class TestTextHelpers(unittest.TestCase):
    def test_clean_strips_tags_entities_and_whitespace(self):
        self.assertEqual(vf.clean("<p>Hallo   &amp;  Welt</p>"), "Hallo & Welt")
        self.assertEqual(vf.clean("Zeile1\n\n   Zeile2"), "Zeile1 Zeile2")

    def test_clean_handles_none_and_empty(self):
        self.assertEqual(vf.clean(None), "")
        self.assertEqual(vf.clean(""), "")

    def test_find_cves_uppercases_and_deduplicates(self):
        found = vf.find_cves("cve-2026-1234 und CVE-2026-1234", "CVE-2013-4786")
        self.assertEqual(found, ["CVE-2026-1234", "CVE-2013-4786"])

    def test_find_cves_ignores_non_matches(self):
        self.assertEqual(vf.find_cves("CVE-26-1", "kein Treffer"), [])


class TestDateParsing(unittest.TestCase):
    def test_rfc822_is_converted_to_utc(self):
        parsed = vf.parse_date("Tue, 28 Jul 2026 17:17:39 -0400")
        self.assertEqual(parsed, datetime(2026, 7, 28, 21, 17, 39, tzinfo=timezone.utc))

    def test_iso8601_with_z_suffix(self):
        parsed = vf.parse_date("2026-07-28T12:15:00.000Z")
        self.assertEqual(parsed, datetime(2026, 7, 28, 12, 15, tzinfo=timezone.utc))

    def test_unparsable_input_returns_none(self):
        for bad in (None, "", "irgendwann", "32.13.2026"):
            self.assertIsNone(vf.parse_date(bad), f"{bad!r} sollte None ergeben")


class TestFeedParsing(unittest.TestCase):
    def test_parse_rss_extracts_fields(self):
        entries = vf.parse_rss(ET.fromstring(RSS_FIXTURE), "Beispiel")
        self.assertEqual(len(entries), 2)
        first = entries[0]
        self.assertEqual(first.source, "Beispiel")
        self.assertEqual(first.title, "vBulletin fixes critical pre-auth RCE flaw")
        self.assertEqual(first.link, "https://example.test/vbulletin-rce/")
        self.assertEqual(first.summary, "A critical vulnerability & more.")
        self.assertEqual(first.published,
                         datetime(2026, 7, 28, 21, 17, 39, tzinfo=timezone.utc))

    def test_parse_atom_extracts_fields_and_cve(self):
        entries = vf.parse_atom(ET.fromstring(ATOM_FIXTURE), "heise")
        self.assertEqual(len(entries), 1)
        only = entries[0]
        self.assertEqual(only.title, "Attacken auf Progress LoadMaster moeglich")
        self.assertEqual(only.link, "https://example.test/loadmaster")
        self.assertEqual(only.cves, ["CVE-2026-59686"])
        self.assertEqual(only.published,
                         datetime(2026, 7, 28, 12, 15, tzinfo=timezone.utc))

    def test_atom_link_missing_yields_empty_string(self):
        feed = ATOM_FIXTURE.replace('<link href="https://example.test/loadmaster"/>', "")
        entries = vf.parse_atom(ET.fromstring(feed), "heise")
        self.assertEqual(entries[0].link, "")


class TestVulnHeuristic(unittest.TestCase):
    def test_advisory_flag_always_counts(self):
        self.assertTrue(entry(title="Voellig neutrale Ankuendigung", advisory=True).is_vuln)

    def test_cve_always_counts(self):
        self.assertTrue(entry(title="Neutral", cves=["CVE-2026-1"]).is_vuln)

    def test_keyword_in_title_counts(self):
        self.assertTrue(entry(title="Kritische Sicherheitslücke in Foo").is_vuln)
        self.assertTrue(entry(title="Critical RCE in Bar").is_vuln)

    def test_keyword_in_summary_counts(self):
        self.assertTrue(entry(title="Foo 2.0", summary="Ein Exploit ist im Umlauf.").is_vuln)

    def test_unrelated_entry_is_filtered_out(self):
        self.assertFalse(entry(title="Neue Kaffeemaschine im Buero",
                               summary="Sie kann jetzt Milchschaum.").is_vuln)


class TestDedupe(unittest.TestCase):
    def test_same_link_appears_once(self):
        entries = [entry(link="https://a.test/x"), entry(link="https://a.test/x"),
                   entry(link="https://a.test/y")]
        self.assertEqual(len(vf.dedupe(entries)), 2)

    def test_falls_back_to_title_when_link_missing(self):
        entries = [entry(link="", title="Gleich"), entry(link="", title="Gleich"),
                   entry(link="", title="Anders")]
        self.assertEqual(len(vf.dedupe(entries)), 2)


class TestSchedule(unittest.TestCase):
    def test_parses_and_sorts_and_deduplicates(self):
        self.assertEqual(vf.parse_schedule("18:00,07:00,07:00"), [(7, 0), (18, 0)])

    def test_tolerates_whitespace_and_single_digit_hour(self):
        self.assertEqual(vf.parse_schedule(" 7:00, 18:30 "), [(7, 0), (18, 30)])

    def test_rejects_invalid_input(self):
        for bad in ("7", "25:00", "07:60", "", "abc", "7:0"):
            with self.assertRaises(vf.ConfigError, msg=f"{bad!r} sollte scheitern"):
                vf.parse_schedule(bad)

    def test_next_run_picks_upcoming_time_today(self):
        times = [(7, 0), (18, 0)]
        now = datetime(2026, 7, 29, 6, 30, tzinfo=timezone.utc)
        self.assertEqual(vf.next_run_at(times, now).hour, 7)

    def test_next_run_rolls_over_to_tomorrow(self):
        times = [(7, 0), (18, 0)]
        now = datetime(2026, 7, 29, 23, 45, tzinfo=timezone.utc)
        nxt = vf.next_run_at(times, now)
        self.assertEqual((nxt.day, nxt.hour), (30, 7))

    def test_exact_match_does_not_run_twice(self):
        # Genau auf der Zielzeit muss der naechste Termin gewaehlt werden,
        # sonst wuerde derselbe Lauf zweimal ausgeloest.
        times = [(7, 0), (18, 0)]
        now = datetime(2026, 7, 29, 7, 0, tzinfo=timezone.utc)
        self.assertEqual(vf.next_run_at(times, now).hour, 18)


class TestState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sub", "seen.json")
        self.addCleanup(self.tmp.cleanup)

    def test_round_trip_creates_directory(self):
        vf.save_seen(self.path, ["https://a.test/1", "https://a.test/2"])
        self.assertEqual(vf.load_seen(self.path), ["https://a.test/1", "https://a.test/2"])

    def test_keep_limit_truncates_oldest(self):
        vf.save_seen(self.path, [f"https://a.test/{i}" for i in range(10)], keep=3)
        self.assertEqual(vf.load_seen(self.path),
                         ["https://a.test/0", "https://a.test/1", "https://a.test/2"])

    def test_missing_file_returns_empty(self):
        self.assertEqual(vf.load_seen(os.path.join(self.tmp.name, "weg.json")), [])

    def test_corrupt_file_returns_empty_instead_of_crashing(self):
        broken = os.path.join(self.tmp.name, "broken.json")
        Path(broken).write_text("{kein json", encoding="utf-8")
        self.assertEqual(vf.load_seen(broken), [])

    def test_written_payload_has_timestamp(self):
        vf.save_seen(self.path, ["https://a.test/1"])
        data = json.loads(Path(self.path).read_text(encoding="utf-8"))
        self.assertIn("updated", data)
        self.assertIn("seen", data)


class TestEnvFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for key in list(os.environ):
            if key.startswith("SECFEED_TEST_"):
                del os.environ[key]

    def test_parses_pairs_and_skips_comments(self):
        path = os.path.join(self.tmp.name, "x.env")
        Path(path).write_text(
            "# Kommentar\n"
            "SECFEED_TEST_A=eins\n"
            "\n"
            "SECFEED_TEST_B='zwei'\n"
            'SECFEED_TEST_C="drei"\n'
            "kaputte zeile ohne gleichheitszeichen\n",
            encoding="utf-8",
        )
        vf.load_env_file(path)
        self.addCleanup(lambda: [os.environ.pop(k, None)
                                for k in ("SECFEED_TEST_A", "SECFEED_TEST_B", "SECFEED_TEST_C")])
        self.assertEqual(os.environ["SECFEED_TEST_A"], "eins")
        self.assertEqual(os.environ["SECFEED_TEST_B"], "zwei")
        self.assertEqual(os.environ["SECFEED_TEST_C"], "drei")

    def test_only_matching_quote_pairs_are_stripped(self):
        """Ein Passwort, das auf ein Anfuehrungszeichen endet, darf nicht
        beschnitten werden - der Fehler zeigte sich sonst nur als
        'authentication failed' beim Relay."""
        path = os.path.join(self.tmp.name, "quotes.env")
        Path(path).write_text(
            "SECFEED_TEST_PAIR_S='umschlossen'\n"
            'SECFEED_TEST_PAIR_D="umschlossen"\n'
            "SECFEED_TEST_TRAIL_S=endetAuf'\n"
            'SECFEED_TEST_TRAIL_D=endetAuf"\n'
            "SECFEED_TEST_LEAD_S='nurVorne\n"
            "SECFEED_TEST_SPECIAL=P@ss$w0rd!\n",
            encoding="utf-8",
        )
        keys = ["SECFEED_TEST_PAIR_S", "SECFEED_TEST_PAIR_D", "SECFEED_TEST_TRAIL_S",
                "SECFEED_TEST_TRAIL_D", "SECFEED_TEST_LEAD_S", "SECFEED_TEST_SPECIAL"]
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in keys])
        vf.load_env_file(path)

        self.assertEqual(os.environ["SECFEED_TEST_PAIR_S"], "umschlossen")
        self.assertEqual(os.environ["SECFEED_TEST_PAIR_D"], "umschlossen")
        self.assertEqual(os.environ["SECFEED_TEST_TRAIL_S"], "endetAuf'")
        self.assertEqual(os.environ["SECFEED_TEST_TRAIL_D"], 'endetAuf"')
        self.assertEqual(os.environ["SECFEED_TEST_LEAD_S"], "'nurVorne")
        self.assertEqual(os.environ["SECFEED_TEST_SPECIAL"], "P@ss$w0rd!")

    def test_existing_environment_wins(self):
        os.environ["SECFEED_TEST_A"] = "vorher"
        self.addCleanup(lambda: os.environ.pop("SECFEED_TEST_A", None))
        path = os.path.join(self.tmp.name, "y.env")
        Path(path).write_text("SECFEED_TEST_A=nachher\n", encoding="utf-8")
        vf.load_env_file(path)
        self.assertEqual(os.environ["SECFEED_TEST_A"], "vorher")


class TestMailConfig(unittest.TestCase):
    def setUp(self):
        self.saved = {k: v for k, v in os.environ.items() if k.startswith("SECFEED_")}
        for key in self.saved:
            del os.environ[key]
        self.addCleanup(self._restore)

    def _restore(self):
        for key in [k for k in os.environ if k.startswith("SECFEED_")]:
            del os.environ[key]
        os.environ.update(self.saved)

    def _args(self, *argv):
        return vf.build_parser().parse_args(list(argv))

    def test_cli_arguments_are_used(self):
        cfg = vf.mail_config_from_env(self._args(
            "--email", "--smtp-host", "relay.test",
            "--mail-from", "a@test.invalid", "--mail-to", "b@test.invalid"))
        self.assertEqual(cfg.host, "relay.test")
        self.assertEqual(cfg.recipients, ["b@test.invalid"])
        self.assertEqual(cfg.security, "starttls")
        self.assertEqual(cfg.port, 587)

    def test_environment_is_used_when_cli_absent(self):
        os.environ.update({
            "SECFEED_SMTP_HOST": "env.test",
            "SECFEED_MAIL_FROM": "from@test.invalid",
            "SECFEED_MAIL_TO": "one@test.invalid, two@test.invalid;three@test.invalid",
        })
        cfg = vf.mail_config_from_env(self._args("--email"))
        self.assertEqual(cfg.host, "env.test")
        self.assertEqual(cfg.recipients,
                         ["one@test.invalid", "two@test.invalid", "three@test.invalid"])

    def test_cli_overrides_environment(self):
        os.environ.update({
            "SECFEED_SMTP_HOST": "env.test",
            "SECFEED_MAIL_FROM": "from@test.invalid",
            "SECFEED_MAIL_TO": "to@test.invalid",
        })
        cfg = vf.mail_config_from_env(self._args("--email", "--smtp-host", "cli.test"))
        self.assertEqual(cfg.host, "cli.test")

    def test_default_port_depends_on_security(self):
        base = ("--email", "--smtp-host", "h", "--mail-from", "a@t.invalid",
                "--mail-to", "b@t.invalid")
        for security, expected in (("none", 25), ("starttls", 587), ("ssl", 465)):
            cfg = vf.mail_config_from_env(self._args(*base, "--smtp-security", security))
            self.assertEqual(cfg.port, expected, f"{security} -> {expected}")

    def test_password_only_from_environment(self):
        os.environ["SECFEED_SMTP_PASSWORD"] = "geheim"
        cfg = vf.mail_config_from_env(self._args(
            "--email", "--smtp-host", "h", "--smtp-user", "u",
            "--mail-from", "a@t.invalid", "--mail-to", "b@t.invalid"))
        self.assertEqual(cfg.password, "geheim")

    def test_missing_values_raise_config_error(self):
        with self.assertRaises(vf.ConfigError) as ctx:
            vf.mail_config_from_env(self._args("--email"))
        message = str(ctx.exception)
        self.assertIn("SECFEED_SMTP_HOST", message)
        self.assertIn("SECFEED_MAIL_FROM", message)
        self.assertIn("SECFEED_MAIL_TO", message)

    def test_unchanged_placeholders_are_rejected(self):
        """Beispielwerte koennen nie funktionieren und aeusserten sich sonst erst
        spaet als DNS-Fehler beim Versand."""
        with self.assertRaises(vf.ConfigError) as ctx:
            vf.mail_config_from_env(self._args(
                "--email", "--smtp-host", "smtp.firma.de",
                "--mail-from", "feed@firma.de", "--mail-to", "max@firma.de"))
        message = str(ctx.exception)
        self.assertIn("Beispielwerte", message)
        self.assertIn("smtp.firma.de", message)

    def test_placeholder_check_is_case_insensitive(self):
        with self.assertRaises(vf.ConfigError):
            vf.mail_config_from_env(self._args(
                "--email", "--smtp-host", "SMTP.Firma.DE",
                "--mail-from", "a@echt.de", "--mail-to", "b@echt.de"))

    def test_real_values_pass(self):
        cfg = vf.mail_config_from_env(self._args(
            "--email", "--smtp-host", "relay.echte-firma.de",
            "--mail-from", "feed@echte-firma.de", "--mail-to", "max@echte-firma.de"))
        self.assertEqual(cfg.host, "relay.echte-firma.de")

    def test_invalid_port_raises_config_error(self):
        with self.assertRaises(vf.ConfigError):
            vf.mail_config_from_env(self._args(
                "--email", "--smtp-host", "h", "--mail-from", "a@t.invalid",
                "--mail-to", "b@t.invalid", "--smtp-port", "keineZahl"))


class TestRendering(unittest.TestCase):
    def test_table_reports_empty_result(self):
        self.assertIn("Keine passenden", vf.render_table([]))

    def test_table_contains_title_and_link(self):
        out = vf.render_table([entry(title="Titel X", link="https://a.test/x")])
        self.assertIn("Titel X", out)
        self.assertIn("https://a.test/x", out)

    def test_markdown_contains_link_syntax(self):
        out = vf.render_markdown([entry(title="Titel X", link="https://a.test/x")])
        self.assertIn("[Titel X](https://a.test/x)", out)

    def test_html_escapes_markup_in_content(self):
        out = vf.render_html([entry(title="<script>alert(1)</script>")], "Untertitel")
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_html_shows_cve_badges(self):
        out = vf.render_html([entry(cves=["CVE-2026-1234"])], "Untertitel")
        self.assertIn("CVE-2026-1234", out)

    def test_html_handles_empty_list(self):
        self.assertIn("Keine neuen Meldungen", vf.render_html([], "Untertitel"))


class TestMessageBuilding(unittest.TestCase):
    def _cfg(self, **kwargs):
        defaults = dict(host="h", port=25, sender="from@test.invalid",
                        recipients=["to@test.invalid"], security="none")
        defaults.update(kwargs)
        return vf.MailConfig(**defaults)

    def test_subject_has_prefix_and_count(self):
        msg = vf.build_message(self._cfg(), [entry(title="Kurzer Titel")], "Untertitel")
        self.assertIn("[SecurityFeed]", msg["Subject"])
        self.assertIn("1 neue Meldung(en)", msg["Subject"])
        self.assertIn("Kurzer Titel", msg["Subject"])

    def test_subject_for_empty_result(self):
        msg = vf.build_message(self._cfg(), [], "Untertitel")
        self.assertIn("keine neuen Meldungen", msg["Subject"])

    def test_long_title_is_truncated(self):
        msg = vf.build_message(self._cfg(), [entry(title="A" * 200)], "Untertitel")
        self.assertIn("...", msg["Subject"])
        self.assertLess(len(msg["Subject"]), 140)

    def test_message_is_multipart_with_both_parts(self):
        msg = vf.build_message(self._cfg(), [entry()], "Untertitel")
        self.assertTrue(msg.is_multipart())
        types = {part.get_content_type() for part in msg.walk()}
        self.assertIn("text/plain", types)
        self.assertIn("text/html", types)

    def test_recipients_are_joined(self):
        cfg = self._cfg(recipients=["a@test.invalid", "b@test.invalid"])
        msg = vf.build_message(cfg, [entry()], "Untertitel")
        self.assertEqual(msg["To"], "a@test.invalid, b@test.invalid")


class FakeSMTP(threading.Thread):
    """Nimmt genau eine Mail an und legt sie in self.received ab."""

    daemon = True

    def __init__(self):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.sock.settimeout(30)
        self.port = self.sock.getsockname()[1]
        self.received: list[str] = []

    def run(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn, conn.makefile("rwb") as stream:
            def reply(line: str) -> None:
                stream.write(line.encode() + b"\r\n")
                stream.flush()

            reply("220 fake ESMTP")
            in_data, body = False, []
            while True:
                raw = stream.readline()
                if not raw:
                    break
                text = raw.decode("utf-8", "replace").rstrip("\r\n")
                if in_data:
                    if text == ".":
                        in_data = False
                        self.received.append("\n".join(body))
                        reply("250 Ok queued")
                    else:
                        body.append(text)
                    continue
                upper = text.upper()
                if upper.startswith(("EHLO", "HELO")):
                    reply("250-fake")
                    reply("250 SIZE 10240000")
                elif upper.startswith(("MAIL FROM", "RCPT TO")):
                    reply("250 Ok")
                elif upper == "DATA":
                    in_data = True
                    reply("354 Send data")
                elif upper == "QUIT":
                    reply("221 Bye")
                    break
                else:
                    reply("250 Ok")


class TestSendMail(unittest.TestCase):
    def test_message_reaches_the_relay(self):
        server = FakeSMTP()
        server.start()
        self.addCleanup(server.sock.close)

        cfg = vf.MailConfig(host="127.0.0.1", port=server.port,
                            sender="from@test.invalid",
                            recipients=["to@test.invalid"], security="none",
                            timeout=15.0)
        msg = vf.build_message(cfg, [entry(title="Zugestellter Titel")], "Untertitel")
        vf.send_mail(cfg, msg)

        server.join(timeout=15)
        self.assertEqual(len(server.received), 1, "genau eine Mail erwartet")
        delivered = server.received[0]
        self.assertIn("Zugestellter Titel", delivered)
        self.assertIn("text/html", delivered)
        self.assertIn("text/plain", delivered)

    def test_unreachable_relay_raises(self):
        # Port 1 ist auf keinem Runner belegt -> Verbindungsfehler.
        cfg = vf.MailConfig(host="127.0.0.1", port=1, sender="from@test.invalid",
                            recipients=["to@test.invalid"], security="none", timeout=5.0)
        msg = vf.build_message(cfg, [entry()], "Untertitel")
        with self.assertRaises(OSError):
            vf.send_mail(cfg, msg)


class TestSmtpErrorHints(unittest.TestCase):
    def _cfg(self):
        return vf.MailConfig(host="relay.test", port=587, sender="a@test.invalid",
                             recipients=["b@test.invalid"], security="starttls")

    def test_dns_failure_names_the_host_and_points_at_dns(self):
        hints = " ".join(vf.smtp_error_hints(
            self._cfg(), socket.gaierror(-5, "No address associated with hostname")))
        self.assertIn("relay.test", hints)
        self.assertIn("DNS", hints)
        self.assertIn("getent hosts relay.test", hints)

    def test_refused_connection_points_at_the_port(self):
        hints = " ".join(vf.smtp_error_hints(self._cfg(), ConnectionRefusedError()))
        self.assertIn("587", hints)
        self.assertIn("nc -vz relay.test 587", hints)

    def test_auth_failure_mentions_app_password(self):
        exc = vf.smtplib.SMTPAuthenticationError(535, b"nope")
        hints = " ".join(vf.smtp_error_hints(self._cfg(), exc))
        self.assertIn("App-Passwort", hints)

    def test_starttls_unsupported_suggests_other_modes(self):
        exc = vf.smtplib.SMTPNotSupportedError("STARTTLS extension not supported")
        hints = " ".join(vf.smtp_error_hints(self._cfg(), exc))
        self.assertIn("ssl", hints)
        self.assertIn("none", hints)

    def test_unknown_error_yields_no_hints(self):
        self.assertEqual(vf.smtp_error_hints(self._cfg(), ValueError("etwas anderes")), [])


class TestSchedulerLoop(unittest.TestCase):
    def test_signal_interrupts_the_wait(self):
        """Ohne Signalbehandlung wuerde der Test bis zur Zielzeit blockieren."""
        args = vf.build_parser().parse_args(["--schedule", "03:00", "--no-state"])
        times = vf.parse_schedule("03:00")

        previous = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)

        def fire():
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

        timer = threading.Timer(1.0, fire)
        timer.start()
        self.addCleanup(timer.cancel)

        started = datetime.now()
        code = vf.run_scheduler(args, None, None, times)
        elapsed = datetime.now() - started

        self.assertEqual(code, 0)
        self.assertLess(elapsed, timedelta(seconds=30),
                        "Scheduler haette sofort abbrechen muessen")


class TestScheduleActivation(unittest.TestCase):
    """SECFEED_SCHEDULE steckt im Container in der Service-Umgebung und wird an
    'docker compose run' durchgereicht. Ein Einzelaufruf dort darf deshalb nicht
    versehentlich den Scheduler starten und haengen bleiben."""

    def setUp(self):
        self.previous = os.environ.pop("SECFEED_SCHEDULE", None)
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.pop("SECFEED_SCHEDULE", None)
        if self.previous is not None:
            os.environ["SECFEED_SCHEDULE"] = self.previous

    def _resolve(self, *argv) -> list[tuple[int, int]] | None:
        """Bildet die Entscheidung aus main() nach: Dauerbetrieb oder Einzellauf?"""
        args = vf.build_parser().parse_args(list(argv))
        if args.once or args.dry_run:
            spec = None
        else:
            spec = args.schedule or os.environ.get("SECFEED_SCHEDULE")
        return vf.parse_schedule(spec) if spec else None

    def test_environment_alone_activates_scheduler(self):
        os.environ["SECFEED_SCHEDULE"] = "07:00,18:00"
        self.assertEqual(self._resolve("--no-state"), [(7, 0), (18, 0)])

    def test_once_forces_single_run_despite_environment(self):
        os.environ["SECFEED_SCHEDULE"] = "07:00,18:00"
        self.assertIsNone(self._resolve("--once", "--no-state"))

    def test_dry_run_forces_single_run_despite_environment(self):
        os.environ["SECFEED_SCHEDULE"] = "07:00,18:00"
        self.assertIsNone(self._resolve("--email", "--dry-run"))

    def test_once_beats_explicit_schedule_flag(self):
        self.assertIsNone(self._resolve("--schedule", "07:00", "--once"))

    def test_without_schedule_it_stays_a_single_run(self):
        self.assertIsNone(self._resolve("--no-state"))


class TestArgumentParsing(unittest.TestCase):
    def test_state_path_respects_no_state(self):
        args = vf.build_parser().parse_args(["--no-state"])
        self.assertIsNone(vf.resolve_state_path(args))

    def test_explicit_state_path_wins(self):
        args = vf.build_parser().parse_args(["--state", "/tmp/x.json"])
        self.assertEqual(vf.resolve_state_path(args), "/tmp/x.json")

    def test_unknown_source_is_rejected(self):
        with self.assertRaises(SystemExit):
            vf.build_parser().parse_args(["--source", "gibtsnicht"])

    def test_all_documented_sources_are_accepted(self):
        for source in ("bleeping", "heise-alerts", "heise-security"):
            args = vf.build_parser().parse_args(["--source", source])
            self.assertEqual(args.source, [source])


if __name__ == "__main__":
    unittest.main(verbosity=2)
