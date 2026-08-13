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


class TestShortTermFalsePositives(unittest.TestCase):
    """'rce' als blosser Teilstring steckt in 'enforced', 'resources' und
    'e-commerce' - das hat harmlose Meldungen als Schwachstellen ausgewiesen."""

    def test_words_merely_containing_rce_are_not_vulnerabilities(self):
        for title in ("Microsoft enforces MFA for all Azure portal sign-ins",
                      "My list of S-Tier HN resources",
                      "E-commerce platform launches new checkout",
                      "Oracle cut its Always Free ARM limits, enforced August 1",
                      "Reinforced concrete and other materials"):
            self.assertFalse(entry(title=title).is_vuln, f"{title!r} ist keine Luecke")

    def test_rce_as_a_word_still_counts(self):
        self.assertTrue(entry(title="Critical RCE in Apache Struts").is_vuln)
        self.assertTrue(entry(title="Pre-auth rce discovered").is_vuln)

    def test_dispatched_is_not_a_patch(self):
        self.assertFalse(entry(title="Orders dispatched within 24 hours").is_vuln)

    def test_patch_as_a_word_still_counts(self):
        self.assertTrue(entry(title="Vendor ships patch for critical issue").is_vuln)


class TestHackerNews(unittest.TestCase):
    SOURCE = vf.Source("hackernews", "Hacker News",
                       "https://hn.algolia.com/api/v1/search_by_date", "hn",
                       always_vuln=True, queries=("vulnerability", "security"),
                       min_points=50)

    PAYLOAD = {
        "hits": [
            {"title": "Twenty One Zero-Days in FFmpeg CVE-2026-1234",
             "url": "https://example.test/ffmpeg", "objectID": "123",
             "created_at": "2026-07-28T12:15:00.000Z", "points": 289},
            {"title": "Tell HN: my account was taken over", "url": None,
             "objectID": "456", "created_at": "2026-07-27T08:00:00.000Z",
             "points": 498, "story_text": "Ein <b>langer</b> Text."},
            {"title": "Launch HN: Acme (YC S26) - deploy agents securely",
             "url": "https://example.test/acme", "objectID": "789",
             "created_at": "2026-07-26T08:00:00.000Z", "points": 80},
            {"title": "", "url": "https://example.test/leer", "objectID": "999",
             "created_at": "2026-07-25T08:00:00.000Z", "points": 60},
        ]
    }

    def test_urls_cover_every_query_with_the_points_threshold(self):
        urls = vf.hn_urls(self.SOURCE)
        self.assertEqual(len(urls), 2)
        for url, query in zip(urls, self.SOURCE.queries):
            self.assertIn(f"query={query}", url)
            self.assertIn("tags=story", url)
            self.assertIn("points", url)
            self.assertIn("50", url)

    def test_story_with_url_links_to_the_article(self):
        entries = vf.parse_hn(self.PAYLOAD, self.SOURCE)
        first = entries[0]
        self.assertEqual(first.link, "https://example.test/ffmpeg")
        self.assertEqual(first.source, "Hacker News")
        self.assertEqual(first.published,
                         datetime(2026, 7, 28, 12, 15, tzinfo=timezone.utc))
        self.assertIn("289 Punkte", first.summary)
        self.assertIn("news.ycombinator.com/item?id=123", first.summary)

    def test_cves_are_extracted_from_the_title(self):
        self.assertEqual(vf.parse_hn(self.PAYLOAD, self.SOURCE)[0].cves,
                         ["CVE-2026-1234"])

    def test_story_without_url_links_to_the_discussion(self):
        second = vf.parse_hn(self.PAYLOAD, self.SOURCE)[1]
        self.assertEqual(second.link, "https://news.ycombinator.com/item?id=456")
        self.assertIn("Ein langer Text.", second.summary)

    def test_launch_hn_and_empty_titles_are_dropped(self):
        titles = [e.title for e in vf.parse_hn(self.PAYLOAD, self.SOURCE)]
        self.assertEqual(len(titles), 2)
        self.assertFalse(any(t.lower().startswith("launch hn") for t in titles))
        self.assertNotIn("", titles)

    def test_missing_hits_key_yields_nothing(self):
        self.assertEqual(vf.parse_hn({}, self.SOURCE), [])

    def test_hackernews_is_a_registered_source(self):
        keys = [s.key for s in vf.SOURCES]
        self.assertIn("hackernews", keys)
        source = next(s for s in vf.SOURCES if s.key == "hackernews")
        self.assertEqual(source.kind, "hn")
        self.assertTrue(source.always_vuln,
                        "Suchbegriff und Punkteschwelle sind hier der Filter")


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


class TestEnvFlag(unittest.TestCase):
    def setUp(self):
        self.addCleanup(lambda: os.environ.pop("SECFEED_TEST_FLAG", None))

    def test_truthy_values(self):
        for raw in ("1", "true", "TRUE", "Yes", "ja", "on", "  1  "):
            os.environ["SECFEED_TEST_FLAG"] = raw
            self.assertTrue(vf.env_flag("SECFEED_TEST_FLAG"), f"{raw!r} sollte wahr sein")

    def test_falsy_values(self):
        for raw in ("0", "false", "nein", "no", "off", ""):
            os.environ["SECFEED_TEST_FLAG"] = raw
            self.assertFalse(vf.env_flag("SECFEED_TEST_FLAG"), f"{raw!r} sollte falsch sein")

    def test_unset_is_false(self):
        os.environ.pop("SECFEED_TEST_FLAG", None)
        self.assertFalse(vf.env_flag("SECFEED_TEST_FLAG"))


class TestFailedSourceReporting(unittest.TestCase):
    """Eine still ausgefallene Quelle sieht sonst aus wie ein ruhiger Tag -
    gerade bei der Leermail als Lebenszeichen waere das irrefuehrend."""

    def _cfg(self):
        return vf.MailConfig(host="h", port=25, sender="a@test.invalid",
                             recipients=["b@test.invalid"], security="none")

    def test_subject_warns_about_failed_sources(self):
        msg = vf.build_message(self._cfg(), [], "Untertitel",
                               ["BleepingComputer: HTTP 403 Forbidden"])
        self.assertIn("keine neuen Meldungen", msg["Subject"])
        self.assertIn("1 Quelle(n) nicht erreichbar", msg["Subject"])

    def test_plain_text_names_the_failed_source(self):
        msg = vf.build_message(self._cfg(), [], "Untertitel",
                               ["BleepingComputer: HTTP 403 Forbidden"])
        body = msg.get_body(("plain",)).get_content()
        self.assertIn("WARNUNG", body)
        self.assertIn("HTTP 403 Forbidden", body)

    def test_html_shows_a_warning_box(self):
        out = vf.render_html([], "Untertitel", ["heise Security: Netzwerkfehler"])
        self.assertIn("Warnung", out)
        self.assertIn("Netzwerkfehler", out)

    def test_clean_run_has_no_warning(self):
        msg = vf.build_message(self._cfg(), [], "Untertitel", [])
        self.assertNotIn("Warnung", msg["Subject"])
        self.assertNotIn("WARNUNG", msg.get_body(("plain",)).get_content())

    def test_plain_text_includes_the_subtitle_as_proof_of_life(self):
        msg = vf.build_message(self._cfg(), [], "Lauf vom 30.07.2026 18:00")
        self.assertIn("Lauf vom 30.07.2026 18:00",
                      msg.get_body(("plain",)).get_content())


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
        for source in ("bleeping", "heise-alerts", "heise-security", "hackernews", "local"):
            args = vf.build_parser().parse_args(["--source", source])
            self.assertEqual(args.source, [source])


# --------------------------------------------------------------------------
# Paketscan
# --------------------------------------------------------------------------

# Die Fortsetzungszeile unter Description sieht wie ein Feld aus und wuerde,
# falsch gelesen, die Version ueberschreiben - genau dafuer steht sie hier.
DPKG_STATUS_FIXTURE = """Package: libssl3
Status: install ok installed
Priority: optional
Architecture: arm64
Source: openssl
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 Version: 9.9-9 gehoert zur Beschreibung, nicht zum Paket.

Package: openssl
Status: install ok installed
Architecture: arm64
Version: 3.0.11-1~deb12u2

Package: python3.11-minimal
Status: install ok installed
Source: python3.11 (3.11.2-6+deb12u3)
Version: 3.11.2-6+deb12u3

Package: altlast
Status: deinstall ok config-files
Version: 1.0-1

Package: halbfertig
Status: install ok half-configured
Version: 2.0-1
"""

DPKG_QUERY_FIXTURE = (
    "installed\topenssl\t3.0.11-1~deb12u2\tlibssl3\n"
    "installed\topenssl\t3.0.11-1~deb12u2\topenssl\n"
    "config-files\taltlast\t1.0-1\taltlast\n"
    "installed\t\t\tohne-quellpaket\n"
    "voellig unbrauchbare zeile\n"
)


class TestDpkgParsing(unittest.TestCase):
    def setUp(self):
        self.packages = {p.name: p for p in vf.parse_dpkg_status(DPKG_STATUS_FIXTURE)}

    def test_binary_package_is_folded_onto_its_source(self):
        # OSV kennt nur Quellpakete - eine Abfrage nach 'libssl3' liefert nichts.
        self.assertIn("openssl", self.packages)
        self.assertNotIn("libssl3", self.packages)
        self.assertEqual(self.packages["openssl"].binaries, ("libssl3", "openssl"))

    def test_source_version_in_parentheses_wins(self):
        self.assertEqual(self.packages["python3.11"].version, "3.11.2-6+deb12u3")
        self.assertEqual(self.packages["python3.11"].binaries, ("python3.11-minimal",))

    def test_continuation_lines_are_not_mistaken_for_fields(self):
        self.assertEqual(self.packages["openssl"].version, "3.0.11-1~deb12u2")

    def test_only_fully_installed_packages_count(self):
        # Konfigurationsreste und halb entpackte Pakete liegen nicht als
        # angreifbarer Code auf der Platte.
        self.assertEqual(set(self.packages), {"openssl", "python3.11"})

    def test_query_output_groups_binaries_per_source(self):
        packages = vf.parse_dpkg_query(DPKG_QUERY_FIXTURE)
        self.assertEqual([p.name for p in packages], ["openssl"])
        self.assertEqual(packages[0].binaries, ("libssl3", "openssl"))

    def test_query_output_skips_unusable_lines(self):
        packages = {p.name for p in vf.parse_dpkg_query(DPKG_QUERY_FIXTURE)}
        self.assertNotIn("altlast", packages)
        self.assertNotIn("", packages)


APK_FIXTURE = """C:Q1eVpkasfsuSNoRy5aAceFsSJZ9BE=
P:libcrypto3
V:3.3.2-r0
A:aarch64
S:1129672
I:4747264
T:Crypto library from openssl
o:openssl
p:so:libcrypto.so.3=3
D:so:libc.musl-aarch64.so.1

C:Q1yg4dUCXQaNXvXqmZfLnzSGvfr8s=
P:libssl3
V:3.3.2-r0
A:aarch64
o:openssl

C:Q1CjQoUq3rSCLcvHFTVKdcpwEG3EE=
P:busybox
V:1.37.0-r12
A:aarch64
T:Size optimized toolbox of many common UNIX utilities

P:kaputt-ohne-version
A:aarch64
"""


class TestApkParsing(unittest.TestCase):
    """Alpine-Container - postgres:17-alpine, n8n, adguardhome - fuehren ihre
    Pakete in /lib/apk/db/installed statt in einer dpkg-Statusdatei."""

    def setUp(self):
        self.packages = {p.name: p for p in vf.parse_apk_installed(APK_FIXTURE)}

    def test_subpackages_are_folded_onto_their_origin(self):
        # OSV kennt auch bei Alpine nur das Ursprungspaket: eine Abfrage nach
        # libssl3 liefert nichts, die nach openssl alles.
        self.assertIn("openssl", self.packages)
        self.assertNotIn("libssl3", self.packages)
        self.assertEqual(self.packages["openssl"].binaries, ("libcrypto3", "libssl3"))
        self.assertEqual(self.packages["openssl"].version, "3.3.2-r0")

    def test_package_without_origin_stands_for_itself(self):
        self.assertEqual(self.packages["busybox"].version, "1.37.0-r12")

    def test_records_without_a_version_are_skipped(self):
        self.assertNotIn("kaputt-ohne-version", self.packages)

    def test_checksum_lines_are_not_mistaken_for_fields(self):
        # "C:Q1..." und "D:so:libc..." enthalten Doppelpunkte im Wert.
        self.assertEqual(set(self.packages), {"openssl", "busybox"})

    def test_alpine_version_becomes_the_osv_ecosystem(self):
        # OSV verlangt genau diese Schreibweise - "Alpine:3.21" und "Alpine"
        # liefern beide nichts.
        self.assertEqual(vf.alpine_ecosystem("3.21.2"), "Alpine:v3.21")
        self.assertEqual(vf.alpine_ecosystem("3.19"), "Alpine:v3.19")
        self.assertIsNone(vf.alpine_ecosystem("edge"))
        self.assertIsNone(vf.alpine_ecosystem(""))


class TestSentinelPerEcosystem(unittest.TestCase):
    """Der Sentinel muss zum Oekosystem passen. Ein Debian-Sentinel liefert
    bei Alpine heute zwar auch nichts - aber nur, weil OSV eine unparsbare
    Version als 'kein Treffer' behandelt. Aenderte sich das je, wuerde die
    Differenz saemtliche Alpine-Funde ausloeschen."""

    def test_debian_style_for_debian_and_ubuntu(self):
        self.assertEqual(vf.sentinel_version("Debian:12"), "999999:0-0")
        self.assertEqual(vf.sentinel_version("Ubuntu:24.04"), "999999:0-0")

    def test_apk_style_for_alpine(self):
        self.assertEqual(vf.sentinel_version("Alpine:v3.21"), "999999.0-r0")
        self.assertIn("-r", vf.sentinel_version("Alpine:v3.21"))
        self.assertNotIn(":", vf.sentinel_version("Alpine:v3.21"))


class TestTrackerLink(unittest.TestCase):
    def test_debian_goes_to_the_debian_tracker(self):
        # Nur der zeigt den Status je Suite.
        self.assertEqual(vf.tracker_url("Debian:12", "openssl"),
                         "https://security-tracker.debian.org/tracker/source-package/openssl")

    def test_alpine_goes_to_osv(self):
        # Alpines Tracker hat keine brauchbare Adresse je Paket - ein Link auf
        # den Debian-Tracker waere fuer ein Alpine-Paket schlicht falsch.
        link = vf.tracker_url("Alpine:v3.21", "openssl")
        self.assertNotIn("debian", link)
        self.assertIn("osv.dev", link)
        self.assertIn("ecosystem=Alpine%3Av3.21", link)
        self.assertIn("q=openssl", link)


class TestDebianRelease(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, name: str, text: str) -> str:
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def _release(self, os_release: str = "", debian_version: str = "") -> str:
        missing = os.path.join(self.tmp.name, "gibtsnicht")
        return vf.debian_release(os_release or missing, debian_version or missing)

    def test_raspberry_pi_os_is_recognised_as_debian(self):
        # Raspberry Pi OS meldet sich in /etc/os-release als Debian - haette es
        # eine eigene ID, wuerde der Scan auf dem Zielgeraet verweigern.
        path = self._write("os-release", 'PRETTY_NAME="Raspberry Pi OS"\n'
                                         'NAME="Debian GNU/Linux"\n'
                                         'VERSION_ID="12"\n'
                                         'VERSION="12 (bookworm)"\n'
                                         "VERSION_CODENAME=bookworm\n"
                                         "ID=debian\n")
        self.assertEqual(self._release(os_release=path), "12")

    def test_codename_is_translated_when_version_id_is_missing(self):
        path = self._write("os-release", "ID=debian\nVERSION_CODENAME=trixie\n")
        self.assertEqual(self._release(os_release=path), "13")

    def test_debian_version_file_is_the_fallback(self):
        self.assertEqual(self._release(debian_version=self._write("dv", "12.5\n")), "12")
        self.assertEqual(self._release(debian_version=self._write("dv2", "trixie/sid\n")), "13")

    def test_foreign_distribution_is_refused_with_a_hint(self):
        path = self._write("os-release", "ID=ubuntu\nVERSION_ID=\"24.04\"\n")
        with self.assertRaises(vf.LocalScanError) as caught:
            self._release(os_release=path)
        self.assertIn("ubuntu", str(caught.exception))
        self.assertIn("--debian-release", str(caught.exception))

    def test_nothing_recognisable_raises(self):
        with self.assertRaises(vf.LocalScanError):
            self._release()

    def test_os_release_quotes_are_stripped(self):
        fields = vf.parse_os_release('ID=debian\nVERSION_ID="12"\n# Kommentar\n')
        self.assertEqual(fields, {"ID": "debian", "VERSION_ID": "12"})


class TestCveId(unittest.TestCase):
    def test_debian_prefix_is_removed(self):
        self.assertEqual(vf.cve_id("DEBIAN-CVE-2025-9230"), "CVE-2025-9230")

    def test_prefixes_of_the_other_distributions_too(self):
        self.assertEqual(vf.cve_id("ALPINE-CVE-2024-13176"), "CVE-2024-13176")
        self.assertEqual(vf.cve_id("UBUNTU-CVE-2022-40735"), "CVE-2022-40735")

    def test_other_identifiers_stay_untouched(self):
        self.assertEqual(vf.cve_id("GHSA-abcd-1234"), "GHSA-abcd-1234")
        self.assertEqual(vf.cve_id("DEBIAN-DSA-5678-1"), "DEBIAN-DSA-5678-1")

    def test_prefix_is_only_dropped_for_a_real_cve(self):
        # CVE_RE verlangt mindestens vier Ziffern im Zaehler. Wird der Rest
        # danach zu keiner gueltigen Nummer, bleibt die OSV-ID unangetastet -
        # sonst entstuende eine Nummer, die es nirgends gibt.
        self.assertEqual(vf.cve_id("DEBIAN-CVE-2024-1"), "DEBIAN-CVE-2024-1")


class TestScanLocal(unittest.TestCase):
    """Der Sentinel-Trick: eine zweite Abfrage mit absurd hoher Version nennt
    genau die Luecken ohne Fix. Was nur die echte Abfrage meldet, schliesst ein
    Update tatsaechlich."""

    def _patch(self, name: str, value) -> None:
        original = getattr(vf, name)
        setattr(vf, name, value)
        self.addCleanup(setattr, vf, name, original)

    def _fake_batch(self, vulns: dict):
        """vulns: Paketname -> (IDs zur echten Version, IDs zum Sentinel)."""
        def fake_batch(queries, timeout):
            self.queries = queries
            answers = []
            for name, version, _ecosystem in queries:
                real, sentinel = vulns.get(name, ([], []))
                passend = version == vf.sentinel_version(_ecosystem)
                answers.append(sentinel if passend else real)
            return answers
        return fake_batch

    def _scan(self, packages: list[vf.Package], vulns: dict, **options) -> list[vf.Entry]:
        self.queries: list[tuple[str, str, str]] = []
        self._patch("installed_packages", lambda opts, timeout: packages)
        self._patch("osv_batch", self._fake_batch(vulns))
        return vf.scan_local(vf.LocalOptions(release="12", **options), 20.0)

    def test_only_the_fixable_difference_is_reported(self):
        entries = self._scan(
            [vf.Package("openssl", "3.0.11-1", ("libssl3", "openssl"))],
            {"openssl": (["DEBIAN-CVE-2024-1001", "DEBIAN-CVE-2024-1002", "DEBIAN-CVE-2024-1003"],
                         ["DEBIAN-CVE-2024-1003"])},
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].cves, ["CVE-2024-1001", "CVE-2024-1002"])
        self.assertIn("2 Luecke(n) mit verfuegbarem Fix", entries[0].title)
        self.assertIn("1 weitere", entries[0].summary)

    def test_each_package_is_asked_twice_with_the_sentinel(self):
        self._scan([vf.Package("openssl", "3.0.11-1")], {})
        self.assertEqual(self.queries, [
            ("openssl", "3.0.11-1", "Debian:12"),
            ("openssl", vf.sentinel_version("Debian:12"), "Debian:12"),
        ])

    def test_package_without_findings_yields_nothing(self):
        self.assertEqual(self._scan([vf.Package("bash", "5.2-1")], {}), [])

    def test_unfixable_findings_are_hidden_by_default(self):
        vulns = {"openssl": (["DEBIAN-CVE-2024-1003"], ["DEBIAN-CVE-2024-1003"])}
        self.assertEqual(self._scan([vf.Package("openssl", "3.0.11-1")], vulns), [])

        entries = self._scan([vf.Package("openssl", "3.0.11-1")], vulns, unfixed=True)
        self.assertIn("ohne Fix", entries[0].title)
        self.assertNotIn("apt install", entries[0].summary)

    def test_truncated_result_is_flagged_instead_of_miscounted(self):
        # Bei erreichter Obergrenze ist die Liste abgeschnitten und die
        # Differenz wertlos - dann lieber ehrlich nichts behaupten.
        many = [f"DEBIAN-CVE-2024-{1000 + i}" for i in range(vf.OSV_RESULT_CAP)]
        entries = self._scan([vf.Package("linux", "6.1-1")], {"linux": (many, many)})
        self.assertIn("sehr viele bekannte Luecken", entries[0].title)
        self.assertNotIn("apt install", entries[0].summary)

    def test_entry_survives_the_topic_and_age_filter(self):
        entries = self._scan([vf.Package("openssl", "3.0.11-1")],
                             {"openssl": (["DEBIAN-CVE-2024-1001"], [])})
        self.assertTrue(entries[0].is_vuln)
        self.assertTrue(entries[0].local)
        self.assertIsNotNone(entries[0].published)
        age = datetime.now(timezone.utc) - entries[0].published
        self.assertLess(age, timedelta(minutes=5), "Scan-Eintraege sind immer aktuell")

    def test_entry_links_to_the_tracker_and_names_the_update_command(self):
        entries = self._scan([vf.Package("openssl", "3.0.11-1", ("libssl3", "openssl"))],
                             {"openssl": (["DEBIAN-CVE-2024-1001"], [])})
        self.assertEqual(entries[0].link,
                         "https://security-tracker.debian.org/tracker/source-package/openssl")
        self.assertIn("apt install --only-upgrade libssl3 openssl", entries[0].summary)

    def test_key_changes_when_a_new_vulnerability_appears(self):
        package = [vf.Package("openssl", "3.0.11-1")]
        first = self._scan(package, {"openssl": (["DEBIAN-CVE-2024-1001"], [])})
        second = self._scan(package, {"openssl": (["DEBIAN-CVE-2024-1001",
                                                   "DEBIAN-CVE-2025-1009"], [])})
        # Gleicher Link, also muesste der Zustand den zweiten Lauf schlucken -
        # der eigene Schluessel verhindert genau das.
        self.assertEqual(first[0].link, second[0].link)
        self.assertNotEqual(first[0].state_key, second[0].state_key)


class TestReminder(unittest.TestCase):
    """Eine Nachricht ist ein Ereignis, ein verwundbares Paket ein Zustand.
    Ohne Wiedervorlage verschwaende der Fund nach der ersten Mail und das
    System saehe fuer immer sauber aus."""

    def _window(self, tage: float, stunden: float) -> str:
        # Auf einem Fensteranfang starten: die Grenzen liegen fest auf dem
        # Zeitstrahl, ein beliebiger Startpunkt laege irgendwo mittendrin.
        start = (datetime.fromtimestamp(tage * 86400 * 3000, timezone.utc)
                 if tage > 0 else datetime(2026, 3, 1, tzinfo=timezone.utc))
        return vf.reminder_window(start + timedelta(hours=stunden), tage)

    def test_window_holds_within_the_interval(self):
        self.assertEqual(self._window(7, 0), self._window(7, 24))
        self.assertEqual(self._window(7, 0), self._window(7, 167))

    def test_window_moves_on_after_the_interval(self):
        self.assertNotEqual(self._window(7, 0), self._window(7, 168))

    def test_reminder_is_at_most_but_not_exactly_the_interval(self):
        # Die Grenze haengt am Zeitstrahl, nicht an der Erstmeldung. Ein Fund
        # kurz davor kommt frueher wieder - der harmlose Fehler, und er spart
        # einen Erstmeldungszeitpunkt je Fund im Zustandsspeicher.
        self.assertNotEqual(self._window(7, 167), self._window(7, 169))

    def test_zero_days_keeps_the_old_report_once_behaviour(self):
        self.assertEqual(self._window(0, 0), self._window(0, 24 * 365))

    def test_unchanged_finding_reappears_in_the_next_window(self):
        package = vf.Package("openssl", "3.0.11-1")
        target = vf.ScanTarget(name="", packages=(package,), ecosystem="Debian:12")
        now = datetime.now(timezone.utc)
        first = vf.local_entry(target, package, ["CVE-2024-1001"], 0, now, "100")
        later = vf.local_entry(target, package, ["CVE-2024-1001"], 0, now, "101")
        self.assertNotEqual(first.state_key, later.state_key)

    def test_unscannable_target_also_comes_back(self):
        skipped = vf.SkippedTarget("alpine", "kein dpkg")
        now = datetime.now(timezone.utc)
        self.assertNotEqual(
            vf.unscanned_entry(skipped, now, "100").state_key,
            vf.unscanned_entry(skipped, now, "101").state_key,
        )

    def test_default_is_weekly(self):
        args = vf.build_parser().parse_args([])
        self.assertEqual(vf.local_options(args).remind_days, 7.0)

    def test_environment_can_change_the_interval(self):
        os.environ["SECFEED_LOCAL_REMIND"] = "2"
        self.addCleanup(os.environ.pop, "SECFEED_LOCAL_REMIND", None)
        args = vf.build_parser().parse_args([])
        self.assertEqual(vf.local_options(args).remind_days, 2.0)

    def test_command_line_beats_the_environment(self):
        os.environ["SECFEED_LOCAL_REMIND"] = "2"
        self.addCleanup(os.environ.pop, "SECFEED_LOCAL_REMIND", None)
        args = vf.build_parser().parse_args(["--local-remind", "30"])
        self.assertEqual(vf.local_options(args).remind_days, 30.0)

    def test_unusable_interval_is_a_configuration_error(self):
        os.environ["SECFEED_LOCAL_REMIND"] = "woechentlich"
        self.addCleanup(os.environ.pop, "SECFEED_LOCAL_REMIND", None)
        with self.assertRaises(vf.ConfigError):
            vf.local_options(vf.build_parser().parse_args([]))
        # Und der Lauf bricht sauber mit Code 2 ab, statt mit einem Traceback.
        self.assertEqual(vf.main(["--no-state", "-s", "local"]), 2)


class TestOsvBatch(unittest.TestCase):
    def _patch_urlopen(self, handler) -> None:
        original = vf.urllib.request.urlopen
        vf.urllib.request.urlopen = handler
        self.addCleanup(setattr, vf.urllib.request, "urlopen", original)

    def _collect_requests(self, results_per_call):
        sent = []

        class Response:
            def __init__(self, payload):
                self.payload = payload

            def read(self):
                return json.dumps(self.payload).encode()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def handler(request, timeout=None):
            body = json.loads(request.data)
            sent.append(body["queries"])
            count = len(body["queries"])
            return Response({"results": results_per_call(count)})

        self._patch_urlopen(handler)
        return sent

    def test_queries_are_split_into_chunks(self):
        sent = self._collect_requests(lambda n: [{} for _ in range(n)])
        queries = [(f"paket{i}", "1.0", "Debian:12") for i in range(vf.OSV_CHUNK + 5)]
        results = vf.osv_batch(queries, 30.0)
        self.assertEqual([len(chunk) for chunk in sent], [vf.OSV_CHUNK, 5])
        self.assertEqual(len(results), len(queries))

    def test_ids_are_extracted_in_order(self):
        self._collect_requests(lambda n: [{"vulns": [{"id": "DEBIAN-CVE-2024-1001"}]}, {}])
        results = vf.osv_batch([("a", "1", "Debian:12"), ("b", "2", "Debian:12")], 30.0)
        self.assertEqual(results, [["DEBIAN-CVE-2024-1001"], []])

    def test_each_query_carries_its_own_ecosystem(self):
        # Host und Container koennen verschiedene Debian-Versionen haben und
        # muessen trotzdem in einen Request passen.
        sent = self._collect_requests(lambda n: [{} for _ in range(n)])
        vf.osv_batch([("a", "1", "Debian:12"), ("b", "2", "Debian:13")], 30.0)
        self.assertEqual([q["package"]["ecosystem"] for q in sent[0]],
                         ["Debian:12", "Debian:13"])

    def test_mismatched_answer_count_is_an_error(self):
        # Sonst verschiebt sich die Zuordnung Paket <-> Antwort still.
        self._collect_requests(lambda n: [{}])
        with self.assertRaises(vf.LocalScanError):
            vf.osv_batch([("a", "1", "Debian:12"), ("b", "2", "Debian:12")], 30.0)


class TestContainerLists(unittest.TestCase):
    """Die Paketlisten der Container legt ein Skript auf dem Host ab.
    SecurityFeed selbst bekommt keinen Docker-Zugriff - der Socket waere
    faktisch root auf dem Pi."""

    STATUS = ("Package: openssl\n"
              "Status: install ok installed\n"
              "Version: 3.0.11-1~deb12u2\n")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    # Auszug aus /lib/apk/db/installed: P Name, V Version, o Ursprungspaket.
    APK = ("C:Q1eVpkasfsuSNoRy5aAceFsSJZ9BE=\n"
           "P:libssl3\n"
           "V:3.3.2-r0\n"
           "A:aarch64\n"
           "o:openssl\n"
           "\n"
           "P:busybox\n"
           "V:1.37.0-r12\n"
           "A:aarch64\n")

    def _container(self, name: str, status: str | None = None,
                   os_release: str | None = "ID=debian\nVERSION_ID=\"12\"\n",
                   unsupported: str | None = None, apk: str | None = None) -> str:
        base = os.path.join(self.dir, name)
        os.makedirs(base, exist_ok=True)
        for filename, text in ((vf.CONTAINER_STATUS_FILE, status),
                               (vf.CONTAINER_APK_FILE, apk),
                               (vf.CONTAINER_OS_RELEASE_FILE, os_release),
                               (vf.CONTAINER_UNSUPPORTED_FILE, unsupported)):
            if text is not None:
                with open(os.path.join(base, filename), "w", encoding="utf-8") as fh:
                    fh.write(text)
        return base

    def test_complete_container_becomes_a_target(self):
        self._container("web", status=self.STATUS)
        targets, skipped = vf.container_targets(self.dir)
        self.assertEqual(skipped, [])
        self.assertEqual(targets[0].name, "web")
        self.assertEqual(targets[0].ecosystem, "Debian:12")
        self.assertEqual([p.name for p in targets[0].packages], ["openssl"])

    def test_unsupported_marker_wins_and_carries_the_reason(self):
        self._container("alpine", unsupported="keine dpkg-Paketliste im Container")
        targets, skipped = vf.container_targets(self.dir)
        self.assertEqual(targets, [])
        self.assertEqual(skipped[0].name, "alpine")
        self.assertIn("dpkg", skipped[0].reason)

    def test_alpine_container_becomes_a_target(self):
        # postgres:17-alpine und Konsorten: apk statt dpkg.
        self._container("db", apk=self.APK,
                        os_release='ID=alpine\nVERSION_ID="3.21.2"\n')
        targets, skipped = vf.container_targets(self.dir)
        self.assertEqual(skipped, [])
        self.assertEqual(targets[0].ecosystem, "Alpine:v3.21")
        # libssl3 gehoert zum Ursprungspaket openssl - danach fragt OSV.
        self.assertEqual([p.name for p in targets[0].packages], ["busybox", "openssl"])

    def test_container_without_os_release_is_skipped_not_guessed(self):
        # Ein bookworm-Host und ein trixie-Container haben verschiedene
        # Fixversionen. Lieber nicht pruefen als gegen die falsche Suite.
        self._container("fremd", status=self.STATUS, os_release=None)
        targets, skipped = vf.container_targets(self.dir)
        self.assertEqual(targets, [])
        self.assertIn("nicht erkennbar", skipped[0].reason)

    def test_unknown_distribution_is_skipped(self):
        self._container("fedora", status=self.STATUS,
                        os_release='ID=fedora\nVERSION_ID="41"\n')
        targets, skipped = vf.container_targets(self.dir)
        self.assertEqual(targets, [])
        self.assertEqual(skipped[0].name, "fedora")

    def test_alpine_edge_is_skipped_rather_than_guessed(self):
        # "edge" hat in der Datenbank kein Gegenstueck.
        self._container("edge", apk=self.APK, os_release="ID=alpine\nVERSION_ID=edge\n")
        targets, skipped = vf.container_targets(self.dir)
        self.assertEqual(targets, [])
        self.assertIn("nicht erkennbar", skipped[0].reason)

    def test_empty_status_file_is_skipped(self):
        self._container("leer", status="")
        _, skipped = vf.container_targets(self.dir)
        self.assertIn("kein installiertes Paket", skipped[0].reason)

    def test_missing_directory_is_reported_not_raised(self):
        targets, skipped = vf.container_targets(os.path.join(self.dir, "weg"))
        self.assertEqual(targets, [])
        self.assertIn("nicht lesbar", skipped[0].reason)

    def test_ecosystem_is_read_from_the_container_itself(self):
        self.assertEqual(vf.container_ecosystem('ID=debian\nVERSION_ID="13"\n'),
                         "Debian:13")
        self.assertEqual(vf.container_ecosystem("VERSION_CODENAME=bookworm\n"),
                         "Debian:12")
        self.assertEqual(vf.container_ecosystem('ID=alpine\nVERSION_ID="3.21.2"\n'),
                         "Alpine:v3.21")
        self.assertIsNone(vf.container_ecosystem('ID=fedora\nVERSION_ID="41"\n'))
        self.assertIsNone(vf.container_ecosystem(""))

    def test_age_of_the_stamp_file(self):
        self.assertIsNone(vf.container_list_age(self.dir))
        stamp = os.path.join(self.dir, vf.CONTAINER_STAMP_FILE)
        with open(stamp, "w", encoding="utf-8") as fh:
            fh.write("")
        self.assertLess(vf.container_list_age(self.dir), timedelta(minutes=5))
        old = datetime.now(timezone.utc) - timedelta(hours=100)
        os.utime(stamp, (old.timestamp(), old.timestamp()))
        self.assertGreater(vf.container_list_age(self.dir), vf.CONTAINER_STAMP_MAX_AGE)


class TestScanAcrossTargets(unittest.TestCase):
    """Host und Container in einem Lauf."""

    STATUS = ("Package: openssl\n"
              "Status: install ok installed\n"
              "Version: 3.0.11-1~deb12u2\n")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.queries = []

    def _patch(self, name: str, value) -> None:
        original = getattr(vf, name)
        setattr(vf, name, value)
        self.addCleanup(setattr, vf, name, original)

    def _container(self, name: str, **files) -> None:
        base = os.path.join(self.tmp.name, name)
        os.makedirs(base, exist_ok=True)
        defaults = {vf.CONTAINER_STATUS_FILE: self.STATUS,
                    vf.CONTAINER_OS_RELEASE_FILE: 'ID=debian\nVERSION_ID="13"\n'}
        defaults.update(files)
        for filename, text in defaults.items():
            with open(os.path.join(base, filename), "w", encoding="utf-8") as fh:
                fh.write(text)

    def _touch_stamp(self) -> None:
        with open(os.path.join(self.tmp.name, vf.CONTAINER_STAMP_FILE),
                  "w", encoding="utf-8") as fh:
            fh.write("")

    def _scan(self, vulns: dict, host_packages=(vf.Package("openssl", "3.0.11-1"),),
              host_error: str | None = None, **options) -> list[vf.Entry]:
        def packages(opts, timeout):
            if host_error:
                raise vf.LocalScanError(host_error)
            return list(host_packages)

        def fake_batch(queries, timeout):
            self.queries = queries
            answers = []
            for name, version, _ecosystem in queries:
                real, sentinel = vulns.get(name, ([], []))
                passend = version == vf.sentinel_version(_ecosystem)
                answers.append(sentinel if passend else real)
            return answers

        self._patch("installed_packages", packages)
        self._patch("osv_batch", fake_batch)
        return vf.scan_local(
            vf.LocalOptions(release="12", containers=self.tmp.name, **options), 20.0
        )

    def test_each_target_is_queried_with_its_own_release(self):
        self._container("web")  # trixie, waehrend der Host bookworm ist
        self._touch_stamp()
        self._scan({})
        self.assertEqual({q[2] for q in self.queries}, {"Debian:12", "Debian:13"})

    def test_findings_name_the_container_they_came_from(self):
        self._container("web")
        self._touch_stamp()
        entries = self._scan({"openssl": (["DEBIAN-CVE-2024-1001"], [])})
        by_source = {e.source: e for e in entries}
        self.assertEqual(set(by_source), {"Lokales System", "Container web"})
        self.assertEqual(by_source["Container web"].affects_local, ["openssl (web)"])
        self.assertEqual(by_source["Lokales System"].affects_local, ["openssl"])

    def test_same_package_on_host_and_container_are_separate_entries(self):
        # Gleicher Link, gleiche CVEs - ohne das Ziel im Schluessel wuerde der
        # Zustand den zweiten Fund schlucken.
        self._container("web")
        self._touch_stamp()
        entries = self._scan({"openssl": (["DEBIAN-CVE-2024-1001"], [])})
        self.assertEqual(len({e.state_key for e in entries}), 2)
        self.assertEqual(len(vf.dedupe(entries)), 2)

    def test_container_finding_points_at_the_image_not_at_apt(self):
        self._container("web")
        self._touch_stamp()
        entries = self._scan({"openssl": (["DEBIAN-CVE-2024-1001"], [])})
        container = next(e for e in entries if e.source == "Container web")
        self.assertNotIn("apt install", container.summary)
        self.assertIn("Basisimage", container.summary)

    def test_unscannable_container_is_reported_not_swallowed(self):
        self._container("alpine", **{vf.CONTAINER_UNSUPPORTED_FILE: "kein dpkg im Image"})
        self._touch_stamp()
        entries = self._scan({})
        note = next(e for e in entries if "nicht pruefbar" in e.title)
        self.assertIn("alpine", note.title)
        self.assertIn("kein dpkg im Image", note.summary)
        self.assertTrue(note.is_vuln, "darf nicht am Themenfilter haengenbleiben")

    def test_failed_host_scan_does_not_stop_the_containers(self):
        self._container("web")
        self._touch_stamp()
        entries = self._scan({"openssl": (["DEBIAN-CVE-2024-1001"], [])},
                             host_error="dpkg-query nicht gefunden")
        self.assertTrue(any(e.source == "Container web" and e.cves for e in entries))
        note = next(e for e in entries if "nicht pruefbar" in e.title)
        self.assertIn("Lokales System", note.title)

    def test_nothing_scannable_at_all_fails_the_source(self):
        with self.assertRaises(vf.LocalScanError) as caught:
            self._scan({}, host_error="dpkg-query nicht gefunden")
        self.assertIn("dpkg-query nicht gefunden", str(caught.exception))

    def test_stale_lists_are_flagged(self):
        # Ein stehengebliebener Timer darf nicht als "alles ruhig" durchgehen.
        self._container("web")
        self._touch_stamp()
        stamp = os.path.join(self.tmp.name, vf.CONTAINER_STAMP_FILE)
        old = datetime.now(timezone.utc) - timedelta(hours=100)
        os.utime(stamp, (old.timestamp(), old.timestamp()))
        entries = self._scan({})
        self.assertTrue(any("veraltet" in e.title for e in entries))

    def test_missing_stamp_counts_as_stale(self):
        self._container("web")
        entries = self._scan({})
        self.assertTrue(any("veraltet" in e.title for e in entries))

    def test_fresh_lists_produce_no_warning(self):
        self._container("web")
        self._touch_stamp()
        entries = self._scan({})
        self.assertFalse(any("veraltet" in e.title for e in entries))

    def test_operational_notes_do_not_count_as_findings(self):
        # "nicht pruefbar" ist eine Betriebsmeldung, kein Befund - sie darf den
        # Betreff nicht mit "betrifft dieses System" faerben.
        self._container("alpine", **{vf.CONTAINER_UNSUPPORTED_FILE: "kein dpkg"})
        self._touch_stamp()
        entries = self._scan({})
        cfg = vf.MailConfig(host="h", port=25, sender="a@b.de", recipients=["c@d.de"])
        subject = vf.build_message(cfg, entries, "Test")["Subject"]
        self.assertNotIn("betreffen dieses System", subject)

    def test_entries_without_a_link_render_everywhere(self):
        self._container("alpine", **{vf.CONTAINER_UNSUPPORTED_FILE: "kein dpkg"})
        self._touch_stamp()
        entries = self._scan({})
        note = [e for e in entries if "nicht pruefbar" in e.title]
        self.assertNotIn('href=""', vf.render_html(note, "Test"))
        self.assertNotIn("]()", vf.render_markdown(note))
        self.assertIn("nicht pruefbar", vf.render_table(note))


class TestLocalCorrelation(unittest.TestCase):
    """Der eigentliche Zweck: nicht 'es gibt eine Luecke', sondern 'sie steckt
    hier drin'."""

    def _entries(self):
        scan = entry(source="Lokales System", title="openssl 3.0.11-1: 1 Luecke(n)",
                     link="https://security-tracker.debian.org/tracker/source-package/openssl",
                     cves=["CVE-2024-2511"], local=True, affects_local=["openssl"])
        hit = entry(title="Angreifer nutzen OpenSSL-Luecke", link="https://example.test/1",
                    cves=["CVE-2024-2511", "CVE-2024-9999"])
        miss = entry(title="Luecke in fremder Software", link="https://example.test/2",
                     cves=["CVE-2030-1000"])
        return scan, hit, miss

    def test_matching_news_entry_names_the_installed_package(self):
        scan, hit, miss = self._entries()
        vf.mark_local_matches([scan, hit, miss])
        self.assertEqual(hit.affects_local, ["openssl"])
        self.assertEqual(miss.affects_local, [])

    def test_without_a_scan_nothing_is_marked(self):
        _, hit, miss = self._entries()
        vf.mark_local_matches([hit, miss])
        self.assertEqual(hit.affects_local, [])

    def test_subject_puts_the_affected_system_first(self):
        scan, hit, miss = self._entries()
        vf.mark_local_matches([scan, hit, miss])
        cfg = vf.MailConfig(host="h", port=25, sender="a@b.de", recipients=["c@d.de"])
        subject = vf.build_message(cfg, [miss, scan, hit], "Test")["Subject"]
        self.assertIn("2 von 3", subject)
        self.assertIn("betreffen dieses System", subject)

    def test_rendering_marks_the_hit_but_not_the_scan_entry(self):
        scan, hit, miss = self._entries()
        vf.mark_local_matches([scan, hit, miss])
        for text in (vf.render_table([scan, hit]), vf.render_markdown([scan, hit]),
                     vf.render_html([scan, hit], "Test")):
            self.assertIn("Betrifft dieses System", text)
            # Beim Scan-Eintrag waere der Hinweis eine Doppelung - der Titel
            # nennt das Paket bereits.
            self.assertEqual(text.count("Betrifft dieses System"), 1)


class TestStateKey(unittest.TestCase):
    def test_explicit_key_wins_over_link(self):
        self.assertEqual(entry(key="local:openssl:1:CVE-2024-1").state_key,
                         "local:openssl:1:CVE-2024-1")

    def test_link_is_the_default(self):
        self.assertEqual(entry(link="https://a.test/1").state_key, "https://a.test/1")

    def test_title_is_the_last_resort(self):
        self.assertEqual(entry(link="", title="Ohne Link").state_key, "Ohne Link")

    def test_dedupe_keeps_entries_that_share_a_link_but_not_a_key(self):
        first = entry(link="https://a.test/pkg", key="local:pkg:1:CVE-2024-1")
        second = entry(link="https://a.test/pkg", key="local:pkg:2:CVE-2025-1")
        self.assertEqual(len(vf.dedupe([first, second])), 2)


class TestCveDisplayCap(unittest.TestCase):
    def test_long_cve_lists_are_shortened(self):
        cves = [f"CVE-2024-{1000 + i}" for i in range(vf.CVE_DISPLAY_CAP + 7)]
        listed, rest = vf.shown_cves(entry(cves=cves))
        self.assertEqual(len(listed), vf.CVE_DISPLAY_CAP)
        self.assertEqual(rest, 7)
        for text in (vf.render_table([entry(cves=cves)]),
                     vf.render_markdown([entry(cves=cves)]),
                     vf.render_html([entry(cves=cves)], "Test")):
            self.assertIn("+7 weitere", text)
            self.assertNotIn(cves[-1], text)

    def test_short_lists_stay_complete(self):
        listed, rest = vf.shown_cves(entry(cves=["CVE-2024-1"]))
        self.assertEqual((listed, rest), (["CVE-2024-1"], 0))
        self.assertNotIn("weitere", vf.render_table([entry(cves=["CVE-2024-1"])]))


class TestSourceSelection(unittest.TestCase):
    def setUp(self):
        self.previous = os.environ.pop("SECFEED_LOCAL", None)
        self.addCleanup(self._restore)

    def _restore(self):
        os.environ.pop("SECFEED_LOCAL", None)
        if self.previous is not None:
            os.environ["SECFEED_LOCAL"] = self.previous

    def _keys(self, *argv) -> list[str]:
        return [s.key for s in vf.select_sources(vf.build_parser().parse_args(list(argv)))]

    def test_scan_stays_out_of_the_default_run(self):
        # Auf einem Nicht-Debian-System scheitert er zwangslaeufig und wuerde
        # jede Mail mit einer Ausfallwarnung verzieren.
        self.assertNotIn("local", self._keys())
        self.assertIn("bleeping", self._keys())

    def test_local_flag_adds_the_scan_to_the_news(self):
        self.assertIn("local", self._keys("--local"))
        self.assertIn("bleeping", self._keys("--local"))

    def test_environment_switch_works_like_the_flag(self):
        os.environ["SECFEED_LOCAL"] = "1"
        self.assertIn("local", self._keys())

    def test_explicit_source_runs_the_scan_alone(self):
        self.assertEqual(self._keys("-s", "local"), ["local"])

    def test_scan_options_reach_the_scanner(self):
        args = vf.build_parser().parse_args(
            ["--dpkg-status", "/host/status", "--debian-release", "11", "--local-unfixed"]
        )
        options = vf.local_options(args)
        self.assertEqual(options.status_path, "/host/status")
        self.assertEqual(options.release, "11")
        self.assertTrue(options.unfixed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
