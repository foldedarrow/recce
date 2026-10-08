# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline UK number-range lookups from Ofcom's numbering data.

Ofcom publishes, weekly, every UK number block (01/02 geographic, 03, 05, 07,
08 and 09) with its status and the communications provider it is allocated
to, plus a table of geographic area codes. recce bundles a compact index
derived from those files (``recce/data/ofcom-numbering.json.xz``) and looks
numbers up locally: no per-query network calls.

The provider is the block's *range holder*: the network the number was
originally allocated to. A ported number is now served by someone else, so
recce labels it "originally allocated to" and never as the current carrier.

``recce update`` refreshes the index into ``~/.cache/recce/``, which wins over
the bundled copy. ``recce update --only ofcom --bundled`` rewrites the bundled
copy in a source checkout.

Data licence: Ofcom material "may be reproduced free of charge in any format
or medium, provided that it is reproduced accurately and not used in a
misleading context", acknowledged as Ofcom copyright with the document title
(https://www.ofcom.org.uk/about-ofcom/our-website/copyright). The index keeps
every field it uses verbatim and carries that attribution in its metadata.
"""

from __future__ import annotations

import csv
import html
import io
import json
import lzma
import re
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import date, datetime
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from ..core.http import HttpClient
from ..core.result import Hit, Status

OFCOM_SITE = "https://www.ofcom.org.uk"
OFCOM_NUMBERING_PAGE = f"{OFCOM_SITE}/phones-and-broadband/phone-numbers/numbering-data"
OFCOM_CODELIST_URL = (
    f"{OFCOM_SITE}/siteassets/resources/documents/phones-telecoms-and-internet/"
    "information-for-industry/numbering/regular-updates/telephone-numbers/codelist.zip"
)
OFCOM_AREA_CODES_URL = f"{OFCOM_SITE}/phones-and-broadband/phone-numbers/telephone-area-codes-tool"
OFCOM_COPYRIGHT_URL = f"{OFCOM_SITE}/about-ofcom/our-website/copyright"

# The number-range files inside codelist.zip. S1 is all 01/02 geographic
# blocks (the sabcde* files are the same rows split by prefix).
NUMBER_FILES = ("S1", "S3", "S5", "S7", "S8", "S9")

INDEX_NAME = "ofcom-numbering.json.xz"
INDEX_FORMAT = 1
CACHE_DIR = Path.home() / ".cache" / "recce"
CACHED_INDEX = CACHE_DIR / INDEX_NAME
# Where `recce update --bundled` writes; reads go through importlib.resources.
BUNDLED_INDEX = Path(__file__).resolve().parent.parent / "data" / INDEX_NAME

ATTRIBUTION = (
    "Contains Ofcom numbering data © Ofcom: 'Download numbering data' "
    "(S1, S3, S5, S7, S8, S9) and 'Telephone area codes'."
)

# Statuses under which numbers in the block can be in service.
_IN_SERVICE = {"allocated", "allocated(closed range)"}

_AREA_ROW_RE = re.compile(
    r'<th[^>]*scope="row"[^>]*>\s*(0\d{2,5})\s*</th>\s*<td[^>]*>(.*?)</td>', re.S
)
_PUBLISH_DATE_RE = re.compile(r"Current files publish date:\s*(\d{1,2} \w+ \d{4})")
_CODELIST_HREF_RE = re.compile(r'href="([^"]*/telephone-numbers/codelist\.zip[^"]*)"')


@dataclass(frozen=True)
class BlockInfo:
    """One Ofcom number block matched for a number."""

    block: str            # masked national number, e.g. "0113 496 0xxx"
    status: str           # Ofcom block status, verbatim
    provider: str         # range holder, "" when unallocated
    allocated: str        # allocation date, ISO, "" when absent
    area: str             # geographic area for 01/02 numbers, else ""

    @property
    def in_service(self) -> bool:
        return self.status.lower() in _IN_SERVICE


@dataclass
class NumberingIndex:
    statuses: list[str]
    providers: list[str]
    # prefix (national significant number digits) -> [status idx, provider idx, yyyymmdd]
    blocks: dict[str, list[Any]]
    # area code without the leading 0 -> area name
    areas: dict[str, str]
    meta: dict[str, str] = field(default_factory=dict)
    _max_len: int = 0

    def __post_init__(self) -> None:
        self._max_len = max((len(p) for p in self.blocks), default=0)

    def area_for(self, nsn: str) -> str:
        for n in range(min(len(nsn), 6), 1, -1):
            name = self.areas.get(nsn[:n])
            if name:
                return name
        return ""

    def lookup(self, nsn: str, national: str = "") -> BlockInfo | None:
        """Longest-prefix match of a UK national significant number. ``national``
        (the formatted national number) only shapes how the block is shown."""
        for n in range(min(len(nsn), self._max_len), 2, -1):
            rec = self.blocks.get(nsn[:n])
            if rec is None:
                continue
            status_i, provider_i, ymd = rec
            area = self.area_for(nsn) if nsn[:1] in ("1", "2") else ""
            return BlockInfo(
                block=_national_block(nsn[:n], national),
                status=self.statuses[status_i],
                provider=self.providers[provider_i],
                allocated=f"{ymd[:4]}-{ymd[4:6]}-{ymd[6:]}" if ymd else "",
                area=area,
            )
        return None


def _national_block(prefix: str, national: str = "") -> str:
    """The block as a masked national number: prefix '1134960' over
    '0113 496 0123' gives '0113 496 0xxx'. Without a formatted number, the
    bare prefix with a trailing ellipsis."""
    keep = len(prefix) + 1  # + the trunk 0
    if national:
        out, seen = [], 0
        for ch in national:
            if ch.isdigit():
                seen += 1
                out.append(ch if seen <= keep else "x")
            else:
                out.append(ch)
        return "".join(out)
    return "0" + prefix + "…"


# ---------------------------------------------------------------------------
# Building the index from Ofcom's files
# ---------------------------------------------------------------------------

def _iso_date(ddmmyyyy: str) -> str:
    try:
        return datetime.strptime(ddmmyyyy.strip(), "%d/%m/%Y").strftime("%Y%m%d")
    except ValueError:
        return ""


def parse_area_codes(page_html: str) -> dict[str, str]:
    """Area-code table from Ofcom's 'Telephone area codes' page, keyed by the
    code without its leading 0."""
    areas: dict[str, str] = {}
    for code, name in _AREA_ROW_RE.findall(page_html):
        clean = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", name))).strip()
        if clean:
            areas[code[1:]] = clean
    return areas


def build_index(
    number_csvs: list[str],
    areas: dict[str, str],
    meta: dict[str, str] | None = None,
) -> NumberingIndex:
    """Index Ofcom number-range CSV texts (S1/S3/S5/S7/S8/S9 layout).

    Unallocated sibling blocks (no provider, same status) are folded into
    their parent prefix. Lookups resolve exactly as before, and allocated
    blocks keep Ofcom's own granularity.
    """
    statuses: dict[str, int] = {}
    providers: dict[str, int] = {"": 0}
    blocks: dict[str, tuple[int, int, str]] = {}
    for text in number_csvs:
        reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
        for row in reader:
            prefix = re.sub(r"\D", "", row.get("NMS Number Block: Number Block") or "")
            status = (row.get("Block Status") or "").strip()
            if not prefix or not status:
                continue
            provider = (row.get("CP Name") or "").strip()
            blocks[prefix] = (
                statuses.setdefault(status, len(statuses)),
                providers.setdefault(provider, len(providers)),
                _iso_date(row.get("Allocation Date") or ""),
            )
    if not blocks:
        raise ValueError("no number blocks found in the Ofcom files")

    _fold_unallocated(blocks)
    return NumberingIndex(
        statuses=list(statuses),
        providers=list(providers),
        blocks={p: list(v) for p, v in sorted(blocks.items())},
        areas=dict(sorted(areas.items())),
        meta={"attribution": ATTRIBUTION, **(meta or {})},
    )


def _fold_unallocated(blocks: dict[str, tuple[int, int, str]]) -> None:
    changed = True
    while changed:
        changed = False
        children: dict[str, list[str]] = {}
        for p in blocks:
            if len(p) > 3:
                children.setdefault(p[:-1], []).append(p)
        for parent, kids in children.items():
            if len(kids) != 10 or parent in blocks:
                continue
            values = {blocks[k] for k in kids}
            if len(values) == 1 and next(iter(values))[1] == 0:
                for k in kids:
                    del blocks[k]
                blocks[parent] = values.pop()
                changed = True


def serialize_index(index: NumberingIndex) -> bytes:
    payload = {
        "format": INDEX_FORMAT,
        "meta": index.meta,
        "statuses": index.statuses,
        "providers": index.providers,
        "areas": index.areas,
        "blocks": index.blocks,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return lzma.compress(raw.encode("utf-8"), preset=9)


def parse_index(data: bytes) -> NumberingIndex:
    payload = json.loads(lzma.decompress(data).decode("utf-8"))
    if payload.get("format") != INDEX_FORMAT:
        raise ValueError(f"unsupported Ofcom index format {payload.get('format')!r}")
    return NumberingIndex(
        statuses=payload["statuses"],
        providers=payload["providers"],
        blocks=payload["blocks"],
        areas=payload["areas"],
        meta=payload.get("meta") or {},
    )


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _bundled_bytes() -> bytes | None:
    try:
        return resources.files("recce.data").joinpath(INDEX_NAME).read_bytes()
    except (FileNotFoundError, OSError):
        return None


@lru_cache(maxsize=1)
def load_index() -> NumberingIndex | None:
    """The refreshed cache if it parses, else the bundled snapshot."""
    if CACHED_INDEX.exists():
        try:
            return parse_index(CACHED_INDEX.read_bytes())
        except (OSError, ValueError, KeyError, lzma.LZMAError):
            pass
    bundled = _bundled_bytes()
    if bundled is None:
        return None
    try:
        return parse_index(bundled)
    except (ValueError, KeyError, lzma.LZMAError):
        return None


def index_status() -> dict[str, Any]:
    index = load_index()
    if index is None:
        return {"loaded": False, "cached": CACHED_INDEX.exists(), "path": str(CACHED_INDEX)}
    return {
        "loaded": True,
        "cached": CACHED_INDEX.exists(),
        "path": str(CACHED_INDEX),
        "blocks": len(index.blocks),
        "published": index.meta.get("published", "?"),
    }


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

def _read_zip_csvs(blob: bytes) -> list[str]:
    wanted = {name.lower() for name in NUMBER_FILES}
    texts: list[str] = []
    found: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for info in zf.infolist():
            stem = Path(info.filename).stem.lower()
            if stem in wanted and info.filename.lower().endswith(".csv"):
                texts.append(zf.read(info).decode("utf-8-sig", errors="replace"))
                found.add(stem)
    missing = wanted - found
    if missing:
        raise RuntimeError(f"Ofcom codelist.zip is missing {', '.join(sorted(missing)).upper()}")
    return texts


def _publish_date(page_html: str) -> str:
    text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", page_html or "")))
    m = _PUBLISH_DATE_RE.search(text)
    if not m:
        return ""
    try:
        return datetime.strptime(m.group(1), "%d %B %Y").date().isoformat()
    except ValueError:
        return ""


async def _get(client: HttpClient, url: str, what: str) -> Any:
    resp = await client.get(url, timeout=120.0)
    if resp is None or resp.status_code != 200:
        code = "?" if resp is None else resp.status_code
        raise RuntimeError(f"Ofcom {what} download failed (HTTP {code})")
    return resp


async def refresh_ofcom_data(client: HttpClient, dest: Path | None = None) -> tuple[int, int]:
    """Download Ofcom's current numbering files, rebuild the index and write
    it to ``dest`` (default: the user cache). Returns (blocks before, after)."""
    before_index = load_index()
    before = len(before_index.blocks) if before_index else 0

    page = await _get(client, OFCOM_NUMBERING_PAGE, "numbering data page")
    href = _CODELIST_HREF_RE.search(page.text)
    zip_url = html.unescape(href.group(1)) if href else OFCOM_CODELIST_URL
    if zip_url.startswith("/"):
        zip_url = OFCOM_SITE + zip_url
    number_csvs = _read_zip_csvs((await _get(client, zip_url, "codelist.zip")).content)
    areas = parse_area_codes((await _get(client, OFCOM_AREA_CODES_URL, "area codes page")).text)
    if len(areas) < 100:
        raise RuntimeError(f"Ofcom area codes page parsed to only {len(areas)} codes")

    index = build_index(
        number_csvs,
        areas,
        meta={
            "published": _publish_date(page.text),
            "built": date.today().isoformat(),
            "source": OFCOM_NUMBERING_PAGE,
            "licence": OFCOM_COPYRIGHT_URL,
        },
    )
    target = dest or CACHED_INDEX
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=target.parent, delete=False) as fh:
        fh.write(serialize_index(index))
        tmp_path = Path(fh.name)
    tmp_path.chmod(0o644)
    tmp_path.replace(target)
    load_index.cache_clear()
    return before, len(index.blocks)


def clear_ofcom_cache() -> bool:
    if not CACHED_INDEX.exists():
        return False
    CACHED_INDEX.unlink()
    load_index.cache_clear()
    return True


# ---------------------------------------------------------------------------
# Phone hit
# ---------------------------------------------------------------------------

def ofcom_hit(nsn: str, national: str = "", index: NumberingIndex | None = None) -> Hit:
    """Range-holder hit for a GB national significant number (no leading 0)."""
    index = index or load_index()
    if index is None:
        return Hit(
            source="Ofcom numbering",
            category="carrier",
            status=Status.ERROR,
            error="Ofcom numbering index unavailable — run `recce update --only ofcom`",
        )
    info = index.lookup(nsn, national)
    published = index.meta.get("published", "")
    as_of = f"Ofcom data {published}" if published else "Ofcom data"
    if info is None:
        return Hit(
            source="Ofcom numbering",
            category="carrier",
            status=Status.NOT_FOUND,
            summary=f"no Ofcom number block covers this number ({as_of})",
            extra={"data_attribution": index.meta.get("attribution", ATTRIBUTION)},
            confidence=0.6,
        )

    parts: list[str] = []
    if info.in_service and info.provider:
        parts.append(f"originally allocated to {info.provider}")
    elif info.provider:
        parts.append(f"block held by {info.provider}")
    else:
        parts.append("not allocated to any provider")
    parts.append(f"block {info.block} · status {info.status}")
    if info.allocated:
        parts.append(f"allocated {info.allocated}")
    if info.area:
        parts.append(f"area: {info.area}")
    if info.in_service:
        parts.append("if the number was ported, its current network differs")
    else:
        parts.append("numbers in this block should not be in service — spoofed or mistyped?")
    parts.append(as_of)

    return Hit(
        source="Ofcom numbering",
        category="carrier",
        status=Status.FOUND if info.in_service else Status.UNKNOWN,
        summary=" · ".join(parts),
        extra={
            "originally_allocated_to": info.provider if info.in_service else "",
            "range_holder": info.provider,
            "block": info.block,
            "block_status": info.status,
            "allocation_date": info.allocated,
            "area": info.area,
            "data_published": published,
            "data_attribution": index.meta.get("attribution", ATTRIBUTION),
        },
        confidence=0.95 if info.in_service else 0.8,
    )
