# SPDX-License-Identifier: AGPL-3.0-or-later
"""Ofcom numbering index. Fixture rows only, and every number looked up is
in an Ofcom drama range (0113 496 0xxx, 01632 960xxx, 020 7946 0xxx,
07700 900xxx); the providers are made up."""

import io
import zipfile

import pytest

from recce.core.result import Status
from recce.modules import ofcom, phone

GEO_CSV = """﻿NMS Number Block: Number Block,Block Status,CP Name,Geographic Number Length,Allocation Date,Notes
1134 95,Allocated,Other Example Telecom Ltd,3+7,15/07/1994,
1134 96 0,Allocated,Example Telecom Ltd,3+7,21/05/1997,
1134 96 1,Quarantined,,3+7,,
""" + "".join(f"1632 96 {d},Protected,,4+6,,\n" for d in range(10))

MOBILE_CSV = """NMS Number Block: Number Block,Block Status,CP Name,Non Geo Number Length,Allocation Date
7700 90,Allocated,Example Mobile Ltd,10 digit numbers,06/11/1995
7700 91,Free,,10 digit numbers,
"""

AREA_HTML = """<table id="allCodes"><thead>
<tr><th scope="col">Code</th><th scope="col">Area</th></tr></thead><tbody>
<tr><th id="r2" scope="row">0113</th><td headers="x">   Leeds   </td></tr>
<tr><th id="r3" scope="row">01632</th><td headers="x">Drama &amp; Fiction</td></tr>
<tr><th id="r4" scope="row">020</th><td headers="x">London</td></tr>
</tbody></table>"""


@pytest.fixture
def index() -> ofcom.NumberingIndex:
    return ofcom.build_index(
        [GEO_CSV, MOBILE_CSV],
        ofcom.parse_area_codes(AREA_HTML),
        meta={"published": "2026-10-07"},
    )


def test_parse_area_codes_strips_zero_and_whitespace() -> None:
    assert ofcom.parse_area_codes(AREA_HTML) == {
        "113": "Leeds",
        "1632": "Drama & Fiction",
        "20": "London",
    }


def test_lookup_longest_prefix_with_area(index: ofcom.NumberingIndex) -> None:
    info = index.lookup("1134960123", "0113 496 0123")
    assert info is not None
    assert info.provider == "Example Telecom Ltd"
    assert info.status == "Allocated"
    assert info.allocated == "1997-05-21"
    assert info.area == "Leeds"
    assert info.block == "0113 496 0xxx"
    assert info.in_service


def test_unallocated_siblings_fold_but_still_resolve(index: ofcom.NumberingIndex) -> None:
    # Ten Protected, provider-less children fold into one parent prefix.
    assert "163296" in index.blocks
    assert not any(p.startswith("163296") and p != "163296" for p in index.blocks)
    info = index.lookup("1632960123", "01632 960123")
    assert info is not None
    assert info.status == "Protected"
    assert info.provider == ""
    assert info.block == "01632 96xxxx"
    assert info.area == "Drama & Fiction"
    assert not info.in_service
    # Allocated blocks are never folded: 1134 96 has a mix.
    assert "1134960" in index.blocks and "1134961" in index.blocks


def test_mobile_has_no_area(index: ofcom.NumberingIndex) -> None:
    info = index.lookup("7700900123", "07700 900123")
    assert info is not None
    assert info.provider == "Example Mobile Ltd"
    assert info.area == ""


def test_serialize_roundtrip(index: ofcom.NumberingIndex) -> None:
    again = ofcom.parse_index(ofcom.serialize_index(index))
    assert again.blocks == index.blocks
    assert again.areas == index.areas
    assert again.meta["published"] == "2026-10-07"
    assert "Ofcom" in again.meta["attribution"]
    assert again.lookup("7700900123") == index.lookup("7700900123")


def test_build_index_rejects_empty_input() -> None:
    with pytest.raises(ValueError):
        ofcom.build_index(["NMS Number Block: Number Block,Block Status,CP Name\n"], {})


def test_hit_labels_original_allocation(index: ofcom.NumberingIndex) -> None:
    hit = ofcom.ofcom_hit("1134960123", "0113 496 0123", index=index)
    assert hit.status is Status.FOUND
    assert hit.category == "carrier"
    assert "originally allocated to Example Telecom Ltd" in (hit.summary or "")
    assert "area: Leeds" in (hit.summary or "")
    assert "ported" in (hit.summary or "")
    assert hit.extra["originally_allocated_to"] == "Example Telecom Ltd"
    assert hit.extra["block_status"] == "Allocated"
    assert hit.extra["data_published"] == "2026-10-07"


def test_hit_for_unallocated_block(index: ofcom.NumberingIndex) -> None:
    hit = ofcom.ofcom_hit("1632960123", "01632 960123", index=index)
    assert hit.status is Status.UNKNOWN
    assert "not allocated to any provider" in (hit.summary or "")
    assert "should not be in service" in (hit.summary or "")
    assert hit.extra["originally_allocated_to"] == ""


def test_hit_for_uncovered_number(index: ofcom.NumberingIndex) -> None:
    hit = ofcom.ofcom_hit("2079460123", "020 7946 0123", index=index)
    assert hit.status is Status.NOT_FOUND


def test_hit_without_index(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ofcom, "load_index", lambda: None)
    hit = ofcom.ofcom_hit("7700900123")
    assert hit.status is Status.ERROR
    assert "recce update" in (hit.error or "")


def test_phone_module_only_queries_uk_plan(monkeypatch, index) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ofcom, "load_index", lambda: index)
    hit = phone._ofcom_hit("+447700900123", "07700 900123")
    assert hit is not None and hit.extra["range_holder"] == "Example Mobile Ltd"
    # ARCEP's fiction range: not +44, so no Ofcom hit at all.
    assert phone._ofcom_hit("+33199001234", "01 99 00 12 34") is None


@pytest.mark.asyncio
async def test_search_phone_adds_ofcom_hit_without_network(monkeypatch, index) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ofcom, "load_index", lambda: index)

    async def no_providers(*a, **kw):  # type: ignore[no-untyped-def]
        return []

    monkeypatch.setattr(phone, "query_registered_providers", no_providers)

    class NoNetwork:
        proxy = None

        async def get(self, *a, **kw):  # type: ignore[no-untyped-def]
            raise AssertionError("phone lookups must not hit the network for Ofcom data")

    report = await phone.search_phone("07700 900123", NoNetwork(), settings=None)  # type: ignore[arg-type]
    hit = next(h for h in report.hits if h.source == "Ofcom numbering")
    assert "originally allocated to Example Mobile Ltd" in (hit.summary or "")


class _Resp:
    def __init__(self, status: int, text: str = "", content: bytes = b"") -> None:
        self.status_code = status
        self.text = text
        self.content = content


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()


@pytest.mark.asyncio
async def test_refresh_builds_index_from_ofcom_files(tmp_path) -> None:  # type: ignore[no-untyped-def]
    empty = "NMS Number Block: Number Block,Block Status,CP Name,Non Geo Number Length,Allocation Date\n"
    blob = _zip({
        "S1.csv": GEO_CSV, "S3.csv": empty, "S5.csv": empty,
        "S7.csv": MOBILE_CSV, "S8.csv": empty, "S9.csv": empty, "RID.csv": "ignored",
    })
    page = (
        '<p>Current files publish date: <strong>7 October&nbsp;2026</strong></p>'
        '<a href="/siteassets/x/telephone-numbers/codelist.zip?v=1">zip</a>'
    )
    area_page = AREA_HTML.replace("</tbody>", "".join(
        f'<tr><th scope="row">01{n:03d}</th><td>Place {n}</td></tr>' for n in range(200, 320)
    ) + "</tbody>")
    calls: list[str] = []

    class Client:
        async def get(self, url, **kw):  # type: ignore[no-untyped-def]
            calls.append(url)
            if url == ofcom.OFCOM_NUMBERING_PAGE:
                return _Resp(200, text=page)
            if url.endswith("codelist.zip?v=1"):
                return _Resp(200, content=blob)
            if url == ofcom.OFCOM_AREA_CODES_URL:
                return _Resp(200, text=area_page)
            return _Resp(404)

    dest = tmp_path / "idx.json.xz"
    _, after = await ofcom.refresh_ofcom_data(Client(), dest=dest)  # type: ignore[arg-type]
    assert calls[1] == ofcom.OFCOM_SITE + "/siteassets/x/telephone-numbers/codelist.zip?v=1"
    built = ofcom.parse_index(dest.read_bytes())
    assert after == len(built.blocks)
    assert built.meta["published"] == "2026-10-07"
    assert built.lookup("7700900123").provider == "Example Mobile Ltd"  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_refresh_fails_when_a_number_file_is_missing(tmp_path) -> None:  # type: ignore[no-untyped-def]
    blob = _zip({"S1.csv": GEO_CSV})

    class Client:
        async def get(self, url, **kw):  # type: ignore[no-untyped-def]
            if url == ofcom.OFCOM_NUMBERING_PAGE:
                return _Resp(200, text="")
            if url == ofcom.OFCOM_CODELIST_URL:
                return _Resp(200, content=blob)
            return _Resp(200, text=AREA_HTML * 50)

    dest = tmp_path / "idx.json.xz"
    with pytest.raises(RuntimeError, match="missing"):
        await ofcom.refresh_ofcom_data(Client(), dest=dest)  # type: ignore[arg-type]
    assert not dest.exists()


def test_bundled_index_loads() -> None:
    index = ofcom.load_index()
    assert index is not None
    assert len(index.blocks) > 100_000
    assert "Allocated" in index.statuses
    assert index.meta.get("published")
