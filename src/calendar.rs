//! Proleptic-Gregorian civil-date conversion from days since the Unix epoch (1970-01-01). Single source for the Howard Hinnant `civil_from_days` algorithm, shared by the log-line timestamp formatter (`logging`) and the AVClient ISO 8601 timestamp formatter (`protect_controller`). Dedicating it here keeps one algorithm in one place: the two prior copies had already diverged in surface form (negative-number handling spelled two ways, `m`/`year` branches ordered differently) and a bug fix in one would not have propagated to the other.

use std::time::{SystemTime, UNIX_EPOCH};

/// Days per solar year, used by the epoch-to-civil-date converter and the seconds-to-days reduction shared by the two callers.
const SECS_PER_DAY: i64 = 86_400;

/// Converts days since the Unix epoch (1970-01-01) to a proleptic-Gregorian `(year, month, day)` triple. Howard Hinnant's `civil_from_days` algorithm (`http://howardhinnant.github.io/date_algorithms.html`), valid for any day count representable as `i64`.
pub fn civil_from_days(z_in: i64) -> (i64, u32, u32) {
    let z = z_in + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

/// Returns the current UTC civil time as `(year, month, day, hour, minute, second)`, derived from `SystemTime` via `civil_from_days`. Exposed so callers that need the wall clock (`logging::format_line`, `onvif_server::GetSystemDateAndTime`) share one `SystemTime`-to-civil reduction rather than each re-deriving the day/second split.
pub fn utc_now() -> (i64, u32, u32, u32, u32, u32) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as i64;
    let days = secs.div_euclid(SECS_PER_DAY);
    let day_secs = secs.rem_euclid(SECS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let hours = (day_secs / 3600) as u32;
    let minutes = ((day_secs % 3600) / 60) as u32;
    let seconds = (day_secs % 60) as u32;
    (year, month, day, hours, minutes, seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_epoch_origin_is_1970_01_01() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_day_20089_is_2025_01_01() {
        // 2025-01-01 00:00:00 UTC = Unix timestamp 1_735_689_600 = day 20_089.
        assert_eq!(civil_from_days(20_089), (2025, 1, 1));
    }

    #[test]
    fn civil_from_days_day_20088_is_2024_12_31() {
        assert_eq!(civil_from_days(20_088), (2024, 12, 31));
    }

    #[test]
    fn civil_from_days_negative_is_pre_epoch() {
        // 1969-12-31 is day -1; the canonical Hinnant form handles negative day counts via the `z - 146_096` floor-division branch.
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }
}
