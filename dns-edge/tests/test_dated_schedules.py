from datetime import datetime
import pytest
from schedules import validate_schedules, is_active, ScheduleError

BASE = dict(name='holiday', days=list(range(7)), start='21:00', end='06:00',
            timezone='America/New_York', block_domains=['games.example'],
            start_date='2026-11-17', end_date='2026-11-17')

def at(s):
    return datetime.fromisoformat(s)

def test_one_time_holiday_overnight():
    s = validate_schedules([BASE])[0]
    assert not is_active(s, at('2026-11-17T02:00:00-05:00'))
    assert is_active(s, at('2026-11-17T22:00:00-05:00'))
    assert is_active(s, at('2026-11-18T02:00:00-05:00'))
    assert not is_active(s, at('2026-11-18T22:00:00-05:00'))
    assert validate_schedules([s]) == [s]

@pytest.mark.parametrize('dates', [dict(start_date='bad'),
    dict(start_date='2026-12-01', end_date='2026-11-01'),
    dict(end_date=123), dict(start_date='2026-11-1')])
def test_bad_dates_refused(dates):
    with pytest.raises(ScheduleError):
        validate_schedules([dict(BASE, **dates)])

def test_dst_fold_both_repeated_minutes_active():
    s = validate_schedules([dict(BASE, start='01:00', end='02:00',
        start_date='2026-11-01', end_date='2026-11-01')])[0]
    assert is_active(s, at('2026-11-01T05:30:00+00:00'))
    assert is_active(s, at('2026-11-01T06:30:00+00:00'))
