"""可注入时钟：所有时间戳与例外到期判断都走这里。"""
from __future__ import annotations

from datetime import datetime, timezone


class Clock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def stamp(self) -> str:
        return self.now().isoformat(timespec="seconds")


class FakeClock(Clock):
    def __init__(self, start: str = "2026-01-01T00:00:00+00:00"):
        self._now = datetime.fromisoformat(start)

    def now(self) -> datetime:
        return self._now

    def advance(self, **kwargs: int) -> None:
        from datetime import timedelta

        self._now = self._now + timedelta(**kwargs)

    def set(self, value: str) -> None:
        self._now = datetime.fromisoformat(value)


def parse_stamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def is_active(expires_at: str | None, clock: Clock) -> bool:
    if expires_at is None:
        return True
    return parse_stamp(expires_at) > clock.now()
