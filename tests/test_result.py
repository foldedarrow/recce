# SPDX-License-Identifier: AGPL-3.0-or-later
from datetime import datetime, timedelta, timezone

from recce.core.result import Report


def test_report_duration_uses_wall_clock_completion() -> None:
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    report = Report(
        query="alice",
        query_type="username",
        started_at=started,
        completed_at=started + timedelta(milliseconds=1250),
    )

    assert report.duration_ms == 1250
