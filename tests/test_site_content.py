"""Content tests: menu labels, schedule/week-page agreement, week-page quality.

Scoped to the published site pages (root pages, core/*.html,
weeks/week-NN.html) so private working files never affect the result.
"""
import re
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

SITE_ROOT = Path(__file__).parent.parent
WEEK_RE = re.compile(r"week-(\d{2})\.html$")

# Menu labels and page names shown to students.
READINGS_LABEL = "Readings"
PROJECTS_LABEL = "Projects"
RETIRED_LABELS = {"Schedule", "Assignments"}

WEEK06_TITLE = "Week 6: AI-SWE with Mini-Project #2 - A Web CMS"

# Common misspellings that have slipped into drafts before.
MISSPELLINGS = [
    "accomodate", "dicussed", "recieve", "seperate", "occured", "definately",
    "untill", "wich", "teh ", "enviroment", "succesful", "refering",
]


def _site_pages():
    pages = sorted(SITE_ROOT.glob("*.html"))
    pages += sorted((SITE_ROOT / "core").glob("*.html"))
    pages += sorted(p for p in (SITE_ROOT / "weeks").glob("week-*.html") if WEEK_RE.search(p.name))
    return pages


def _soup(path):
    return BeautifulSoup(path.read_text(encoding="utf-8"), "lxml")


def _rel(path):
    return str(path.relative_to(SITE_ROOT))


def _schedule_week_links():
    """(nn, link_text, enabled) for every week link on core/schedule.html."""
    soup = _soup(SITE_ROOT / "core" / "schedule.html")
    out = []
    for a in soup.select(".page-content a[href]"):
        m = WEEK_RE.search(a["href"])
        if m:
            enabled = "link-disabled" not in (a.get("class") or []) and a.get("aria-disabled") != "true"
            out.append((m.group(1), a.get_text(" ", strip=True), enabled))
    return out


class TestMenuLabels:
    def test_no_page_uses_retired_menu_labels(self):
        """Nav menus say Readings/Projects, never Schedule/Assignments."""
        bad = []
        for p in _site_pages():
            nav = _soup(p).select_one("nav.main-nav")
            if nav is None:
                continue
            labels = {a.get_text(strip=True) for a in nav.find_all("a")}
            if labels & RETIRED_LABELS:
                bad.append(f"{_rel(p)}: {sorted(labels & RETIRED_LABELS)}")
        assert not bad, bad

    def test_nav_label_points_at_expected_page(self):
        """Readings -> core/schedule.html, Projects -> core/assignments.html (URLs unchanged)."""
        bad = []
        for p in _site_pages():
            nav = _soup(p).select_one("nav.main-nav")
            if nav is None:
                continue
            for a in nav.find_all("a"):
                label, href = a.get_text(strip=True), a.get("href", "")
                target = (SITE_ROOT / href.lstrip("/")) if href.startswith("/") else (p.parent / href)
                target = target.resolve()
                if label == READINGS_LABEL and target != (SITE_ROOT / "core" / "schedule.html").resolve():
                    bad.append(f"{_rel(p)}: Readings -> {href}")
                if label == PROJECTS_LABEL and target != (SITE_ROOT / "core" / "assignments.html").resolve():
                    bad.append(f"{_rel(p)}: Projects -> {href}")
        assert not bad, bad

    @pytest.mark.parametrize("page,label", [
        ("core/schedule.html", READINGS_LABEL),
        ("core/assignments.html", PROJECTS_LABEL),
    ])
    def test_renamed_page_title_hero_breadcrumb(self, page, label):
        soup = _soup(SITE_ROOT / page)
        assert soup.title.get_text().startswith(f"{label} – "), soup.title.get_text()
        assert soup.select_one("section.hero h1").get_text(strip=True) == label
        assert soup.select_one(".breadcrumbs span").get_text(strip=True) == label

    def test_week_breadcrumbs_say_readings(self):
        bad = []
        for p in (SITE_ROOT / "weeks").glob("week-*.html"):
            if not WEEK_RE.search(p.name):
                continue
            crumbs = [a.get_text(strip=True) for a in _soup(p).select(".breadcrumbs a")]
            if crumbs != ["Home", READINGS_LABEL]:
                bad.append(f"{_rel(p)}: {crumbs}")
        assert not bad, bad

    def test_body_links_to_renamed_pages_use_new_labels(self):
        """In-body links (quick links, cross-references) to the renamed pages use the new labels."""
        bad = []
        for p in _site_pages():
            body = _soup(p).select_one(".page-content")
            if body is None:
                continue
            for a in body.find_all("a", href=True):
                text = a.get_text(strip=True)
                if a["href"].endswith("schedule.html") and text in RETIRED_LABELS:
                    bad.append(f"{_rel(p)}: {text}")
                if a["href"].endswith("assignments.html") and text in RETIRED_LABELS:
                    bad.append(f"{_rel(p)}: {text}")
        assert not bad, bad


class TestScheduleAgreesWithWeekPages:
    def test_enabled_links_go_to_live_pages_with_matching_title(self):
        """An active schedule link opens a published page whose <h1> equals the link text."""
        bad = []
        for nn, text, enabled in _schedule_week_links():
            soup = _soup(SITE_ROOT / "weeks" / f"week-{nn}.html")
            h1 = soup.select_one("section.hero h1").get_text(" ", strip=True)
            pending = soup.select_one(".notice-pending") is not None
            if enabled and pending:
                bad.append(f"week {nn}: link active but page is PENDING")
            if enabled and h1 != text:
                bad.append(f"week {nn}: link '{text}' != page h1 '{h1}'")
            if not enabled and not pending:
                bad.append(f"week {nn}: page is live but schedule link is disabled")
        assert not bad, bad


@pytest.fixture(scope="module")
def page():
    return _soup(SITE_ROOT / "weeks" / "week-06.html")


@pytest.fixture(scope="module")
def live_weeks():
    out = []
    for p in sorted((SITE_ROOT / "weeks").glob("week-*.html")):
        if WEEK_RE.search(p.name):
            soup = _soup(p)
            if soup.select_one(".notice-pending") is None:
                out.append((p, soup))
    return out


class TestWeek06:
    def test_schedule_link_active_with_title(self):
        links = {nn: (text, enabled) for nn, text, enabled in _schedule_week_links()}
        assert links["06"] == (WEEK06_TITLE, True)

    def test_title_and_hero(self, page):
        assert page.select_one("section.hero h1").get_text(" ", strip=True) == WEEK06_TITLE
        assert page.title.get_text() == f"{WEEK06_TITLE} – IPHS 400: Frontiers in AI"

    def test_is_live(self, page):
        assert page.select_one(".notice-pending") is None
        assert "sync:state live" in (SITE_ROOT / "weeks" / "week-06.html").read_text(encoding="utf-8")

    def test_section_structure_and_dates(self, page):
        h2 = [h.get_text(strip=True) for h in page.select(".page-content h2")]
        assert h2 == ["Introduction", "Tuesday (Sep 29, 2026)", "Thursday (Oct 1, 2026)"]
        h3 = [h.get_text(strip=True) for h in page.select(".page-content h3")]
        assert h3 == ["Presentations", "Readings", "Coding"] * 2

    def test_expected_links_present(self, page):
        hrefs = {a["href"] for a in page.select(".page-content a[href]")}
        for must in [
            "https://www.youtube.com/watch?v=7XWV0gA9he0",
            "https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/prompting-claude-opus-5-5",
            "https://www.youtube.com/watch?v=e9lnsKot_SQ",
            "https://www.youtube.com/watch?v=zXysLUTLjw4",
            "https://www.youtube.com/watch?v=bBMp5tLxShQ",
            "https://www.youtube.com/watch?v=o_Cm6idv6dg",
            "https://github.com/jon-chun/iphs400-mp2-cms-starter",
            "week-05.html",
        ]:
            assert must in hrefs, must
        assert any("bairesdev-survey" in h for h in hrefs)

    def test_final_due_date_stated(self, page):
        intro = page.select_one(".page-content p").get_text(" ", strip=True)
        assert "Tuesday, Oct 6" in intro


class TestWeekPageQuality:
    def test_no_tracking_params_in_links(self, live_weeks):
        bad = [f"{_rel(p)}: {a['href']}" for p, s in live_weeks
               for a in s.select("a[href]") if re.search(r"[?&]utm_", a["href"])]
        assert not bad, bad

    def test_no_known_misspellings(self, live_weeks):
        bad = []
        for p, s in live_weeks:
            text = s.select_one(".page-content").get_text(" ").lower()
            bad += [f"{_rel(p)}: {w.strip()}" for w in MISSPELLINGS if w in text]
        assert not bad, bad

    def test_list_items_are_tight(self, live_weeks):
        """No <p> inside <li>: loose markdown lists render with extra spacing."""
        bad = [_rel(p) for p, s in live_weeks if s.select(".page-content li > p")]
        assert not bad, bad

    def test_every_link_has_text(self, live_weeks):
        bad = [f"{_rel(p)}: {a['href']}" for p, s in live_weeks
               for a in s.select(".page-content a[href]") if not a.get_text(strip=True)]
        assert not bad, bad
