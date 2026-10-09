# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

pytest.importorskip("streamlit")
from recce.gui import theme


def test_card_escapes_site_text_and_keeps_one_html_block() -> None:
    markup = theme.card(
        "<b>Site</b>",
        url="https://example.test/u/x?a=1&b=2",
        body='bio: <img src=x onerror="alert(1)">\n\nline after a blank line',
        signals=["same avatar\n\n<script>"],
    )
    assert "<img" not in markup and "<script>" not in markup and "<b>Site" not in markup
    assert "&lt;img" in markup
    assert "\n" not in markup  # a blank line would end st.markdown's raw HTML block
    assert 'href="https://example.test/u/x?a=1&amp;b=2"' in markup


@pytest.mark.parametrize(
    "url",
    ["javascript:alert(1)", "data:text/html,x", "JaVaScRiPt:alert(1)", "https://a.test/\nx", "", None],
)
def test_links_only_for_http_urls(url: str | None) -> None:
    assert theme.safe_url(url) is None
    assert "href" not in theme.link(url)


def test_chip_tooltip_escaped_once() -> None:
    markup = theme.chip("exit", "tor & home")
    assert 'title="exit · tor &amp; home"' in markup
    assert "&amp;amp;" not in markup


def test_theme_flags_pair_up() -> None:
    flags = theme.THEME_FLAGS
    assert len(flags) % 2 == 0
    assert all(flag.startswith("--theme.") for flag in flags[::2])
