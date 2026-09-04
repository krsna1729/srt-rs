/// Parse a CPU set spec: comma-separated indices and inclusive ranges,
/// e.g. `"0-2"`, `"0,2,4"`, `"0-1,4-5"`. Empty means "leave it alone".
///
/// A list rather than a count because sender and receiver need *disjoint*
/// sets, not just budgets: giving each "4 CPUs" starting from 0 would
/// place them on the same cores and have them fight.
#[must_use]
pub fn parse_cpu_spec(spec: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((lo, hi)) => {
                if let (Ok(lo), Ok(hi)) = (lo.trim().parse(), hi.trim().parse::<usize>()) {
                    for cpu in lo..=hi {
                        cpus.push(cpu);
                    }
                }
            }
            None => {
                if let Ok(cpu) = part.parse() {
                    cpus.push(cpu);
                }
            }
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    cpus
}

/// Restrict this process to `cpus`.
///
/// Benchmarks that do not say how much CPU they were given are not
/// reproducible: the same binary on a 6-core and a 64-core host is two
/// different experiments. Pinning the two roles to disjoint sets goes
/// further -- it stops the sender and receiver competing, so a listener
/// that is compute-bound can be given cores without the load generator
/// taking them back.
///
/// An empty slice leaves the inherited mask alone.
pub fn restrict_to_cpu_list(cpus: &[usize]) -> std::io::Result<()> {
    if cpus.is_empty() {
        return Ok(());
    }
    // SAFETY: `set` has the exact libc type and is initialized before use;
    // indices are checked against `CPU_SETSIZE`, and the syscall only reads
    // the set during the call.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for &cpu in cpus {
            if cpu < libc::CPU_SETSIZE as usize {
                libc::CPU_SET(cpu, &mut set);
            }
        }
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// How many logical CPUs this process may currently run on.
#[must_use]
pub fn available_cpus() -> usize {
    // SAFETY: `set` is valid writable storage of the exact size supplied to
    // the syscall. On success CPU_ISSET reads only the initialized result.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
            return std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        }
        (0..libc::CPU_SETSIZE as usize)
            .filter(|cpu| libc::CPU_ISSET(*cpu, &set))
            .count()
            .max(1)
    }
}

/// Format a list of CPU indices into a compact canonical range specification,
/// e.g. `[0, 1, 2, 4, 5]` -> `"0-2,4-5"`, `[3]` -> `"3"`.
#[must_use]
fn format_cpu_spec(cpus: &[usize]) -> String {
    if cpus.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    let mut start = cpus[0];
    let mut prev = cpus[0];
    for &cpu in &cpus[1..] {
        if cpu == prev + 1 {
            prev = cpu;
        } else {
            if start == prev {
                parts.push(format!("{start}"));
            } else {
                parts.push(format!("{start}-{prev}"));
            }
            start = cpu;
            prev = cpu;
        }
    }
    if start == prev {
        parts.push(format!("{start}"));
    } else {
        parts.push(format!("{start}-{prev}"));
    }
    parts.join(",")
}

/// Canonical CPU set string for this process's current affinity mask, e.g. `"0-3"`.
pub fn current_cpu_spec() -> std::io::Result<String> {
    // SAFETY: `set` is valid writable storage of the exact size supplied to
    // the syscall. On success CPU_ISSET reads only the initialized result.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let cpus = (0..libc::CPU_SETSIZE as usize)
            .filter(|cpu| libc::CPU_ISSET(*cpu, &set))
            .collect::<Vec<_>>();
        Ok(format_cpu_spec(&cpus))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_spec_yields_empty() {
        assert!(parse_cpu_spec("").is_empty());
        assert!(parse_cpu_spec("  ").is_empty());
    }

    #[test]
    fn single_cpu() {
        assert_eq!(parse_cpu_spec("3"), vec![3]);
    }

    #[test]
    fn csv_list() {
        assert_eq!(parse_cpu_spec("0,2,4"), vec![0, 2, 4]);
    }

    #[test]
    fn range() {
        assert_eq!(parse_cpu_spec("0-3"), vec![0, 1, 2, 3]);
    }

    #[test]
    fn mixed_range_and_scalar() {
        assert_eq!(parse_cpu_spec("0-1,4-5"), vec![0, 1, 4, 5]);
    }

    #[test]
    fn duplicates_removed_and_sorted() {
        assert_eq!(parse_cpu_spec("3,1,3,0-2"), vec![0, 1, 2, 3]);
    }

    #[test]
    fn whitespace_tolerated() {
        assert_eq!(parse_cpu_spec(" 1 , 3 - 5 "), vec![1, 3, 4, 5]);
    }

    #[test]
    fn garbage_parts_skipped() {
        assert_eq!(parse_cpu_spec("0,abc,2"), vec![0, 2]);
    }

    #[test]
    fn available_cpus_is_nonzero() {
        assert!(available_cpus() >= 1);
    }

    #[test]
    fn format_cpu_spec_empty() {
        assert_eq!(format_cpu_spec(&[]), "");
    }

    #[test]
    fn format_cpu_spec_scalar_and_ranges() {
        assert_eq!(format_cpu_spec(&[3]), "3");
        assert_eq!(format_cpu_spec(&[0, 1]), "0-1");
        assert_eq!(format_cpu_spec(&[0, 1, 2, 3]), "0-3");
        assert_eq!(format_cpu_spec(&[0, 2, 4]), "0,2,4");
        assert_eq!(format_cpu_spec(&[0, 1, 4, 5]), "0-1,4-5");
    }

    #[test]
    fn current_cpu_spec_is_nonempty() {
        let spec = current_cpu_spec().unwrap();
        assert!(!spec.is_empty());
        let parsed = parse_cpu_spec(&spec);
        assert_eq!(parsed.len(), available_cpus());
    }

    proptest! {
        #[test]
        fn formatted_cpu_sets_round_trip(mut cpus in proptest::collection::vec(0usize..256, 0..64)) {
            cpus.sort_unstable();
            cpus.dedup();
            prop_assert_eq!(parse_cpu_spec(&format_cpu_spec(&cpus)), cpus);
        }
    }
}
