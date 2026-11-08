window.BENCHMARK_DATA = {
  "lastUpdate": 1794134725356,
  "repoUrl": "https://github.com/krsna1729/srt-rs",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "name": "Saikrishna Edupuganti",
            "username": "krsna1729",
            "email": "6157640+krsna1729@users.noreply.github.com"
          },
          "committer": {
            "name": "Saikrishna Edupuganti",
            "username": "krsna1729",
            "email": "6157640+krsna1729@users.noreply.github.com"
          },
          "id": "cae714ec6f7ab88f183671c95e911738df1d3254",
          "message": "ci(bench): chart a fixed trend plan that always finishes\n\nProblem: neither benchmark trend has moved since 2026-10-13.\n- Bench nightly charted throughput-matrix.plan (768 cells) only when it\n  finished inside a 5h box; it never did (about 510 cells, mio and tokio\n  only), so the chart step was skipped every night (6 of 6 checked).\n- Bench weekly ran breadth (~40 min), a 3h throughput box and a fixed\n  150-minute full-matrix slice: 370+ minutes against the 360-minute job\n  limit, so it was cancelled 3 weeks running before charting anything.\n\nChange:\n- New docs/plans/throughput-trend.plan: 48 cells (3 runtimes x 2 ingress\n  x 2 encryption x 200/1200 connections x 1/4 Mbit/s) with\n  throughput-matrix.plan's fixed baseline. Both workflows run it with no\n  time box and chart only it: every point is the same cells measured to\n  completion. Nightly runs 1 rep, weekly 3.\n- The exploratory runs (nightly throughput-matrix sweep, weekly\n  full-matrix slice) get the job time left, minus 20 minutes for the\n  report/chart/upload steps, instead of fixed boxes. They keep their TSV\n  artifacts and never chart.\n- The trend charts get fresh gh-pages series, dev/bench-nightly-trend and\n  dev/bench-weekly-trend: dev/bench-nightly holds three 2026-10 points\n  from throughput-matrix.plan under the same per-runtime names, and\n  mixing them would draw a false step.\n- Weekly no longer runs throughput-matrix.plan: it duplicated the nightly\n  exploration at the same rep count.\n\nEvidence:\n- Last completed nightly (run 41392028037): 508 throughput cells in 5h;\n  steps before the sweep take 16 minutes.\n- Local (this host, release srt-bench): throughput-trend.plan --reps 1\n  ran 48 cells (96 rows) in 1,807 s, exit 0; the github-benchmark report\n  gives one median pkt/s series per runtime (compio 12,094; mio 35,633;\n  tokio 22,937).",
          "timestamp": "2026-11-03T06:14:21Z",
          "url": "https://github.com/krsna1729/srt-rs/commit/cae714ec6f7ab88f183671c95e911738df1d3254"
        },
        "date": 1793711962892,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 29147.6,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 74680.6,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 46997.5,
            "unit": "pkt/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Saikrishna Edupuganti",
            "username": "krsna1729",
            "email": "6157640+krsna1729@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "9fecafab7b3b0ecc30e5f06c4f39bf5ddac53a5c",
          "message": "ci(bench): chart a fixed trend plan that always finishes (#182)\n\nProblem: neither benchmark trend has moved since 2026-10-13.\n- Bench nightly charted throughput-matrix.plan (768 cells) only when it\n  finished inside a 5h box; it never did (about 510 cells, mio and tokio\n  only), so the chart step was skipped every night (6 of 6 checked).\n- Bench weekly ran breadth (~40 min), a 3h throughput box and a fixed\n  150-minute full-matrix slice: 370+ minutes against the 360-minute job\n  limit, so it was cancelled 3 weeks running before charting anything.\n\nChange:\n- New docs/plans/throughput-trend.plan: 48 cells (3 runtimes x 2 ingress\n  x 2 encryption x 200/1200 connections x 1/4 Mbit/s) with\n  throughput-matrix.plan's fixed baseline. Both workflows run it with no\n  time box and chart only it: every point is the same cells measured to\n  completion. Nightly runs 1 rep, weekly 3.\n- The exploratory runs (nightly throughput-matrix sweep, weekly\n  full-matrix slice) get the job time left, minus 20 minutes for the\n  report/chart/upload steps, instead of fixed boxes. They keep their TSV\n  artifacts and never chart.\n- The trend charts get fresh gh-pages series, dev/bench-nightly-trend and\n  dev/bench-weekly-trend: dev/bench-nightly holds three 2026-10 points\n  from throughput-matrix.plan under the same per-runtime names, and\n  mixing them would draw a false step.\n- Weekly no longer runs throughput-matrix.plan: it duplicated the nightly\n  exploration at the same rep count.\n\nEvidence:\n- Last completed nightly (run 41392028037): 508 throughput cells in 5h;\n  steps before the sweep take 16 minutes.\n- Local (this host, release srt-bench): throughput-trend.plan --reps 1\n  ran 48 cells (96 rows) in 1,807 s, exit 0; the github-benchmark report\n  gives one median pkt/s series per runtime (compio 12,094; mio 35,633;\n  tokio 22,937).",
          "timestamp": "2026-11-03T13:22:11Z",
          "url": "https://github.com/krsna1729/srt-rs/commit/9fecafab7b3b0ecc30e5f06c4f39bf5ddac53a5c"
        },
        "date": 1793789134668,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 24828.1,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 57042.6,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 38240.8,
            "unit": "pkt/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Saikrishna Edupuganti",
            "username": "krsna1729",
            "email": "6157640+krsna1729@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "9fecafab7b3b0ecc30e5f06c4f39bf5ddac53a5c",
          "message": "ci(bench): chart a fixed trend plan that always finishes (#182)\n\nProblem: neither benchmark trend has moved since 2026-10-13.\n- Bench nightly charted throughput-matrix.plan (768 cells) only when it\n  finished inside a 5h box; it never did (about 510 cells, mio and tokio\n  only), so the chart step was skipped every night (6 of 6 checked).\n- Bench weekly ran breadth (~40 min), a 3h throughput box and a fixed\n  150-minute full-matrix slice: 370+ minutes against the 360-minute job\n  limit, so it was cancelled 3 weeks running before charting anything.\n\nChange:\n- New docs/plans/throughput-trend.plan: 48 cells (3 runtimes x 2 ingress\n  x 2 encryption x 200/1200 connections x 1/4 Mbit/s) with\n  throughput-matrix.plan's fixed baseline. Both workflows run it with no\n  time box and chart only it: every point is the same cells measured to\n  completion. Nightly runs 1 rep, weekly 3.\n- The exploratory runs (nightly throughput-matrix sweep, weekly\n  full-matrix slice) get the job time left, minus 20 minutes for the\n  report/chart/upload steps, instead of fixed boxes. They keep their TSV\n  artifacts and never chart.\n- The trend charts get fresh gh-pages series, dev/bench-nightly-trend and\n  dev/bench-weekly-trend: dev/bench-nightly holds three 2026-10 points\n  from throughput-matrix.plan under the same per-runtime names, and\n  mixing them would draw a false step.\n- Weekly no longer runs throughput-matrix.plan: it duplicated the nightly\n  exploration at the same rep count.\n\nEvidence:\n- Last completed nightly (run 41392028037): 508 throughput cells in 5h;\n  steps before the sweep take 16 minutes.\n- Local (this host, release srt-bench): throughput-trend.plan --reps 1\n  ran 48 cells (96 rows) in 1,807 s, exit 0; the github-benchmark report\n  gives one median pkt/s series per runtime (compio 12,094; mio 35,633;\n  tokio 22,937).",
          "timestamp": "2026-11-03T13:22:11Z",
          "url": "https://github.com/krsna1729/srt-rs/commit/9fecafab7b3b0ecc30e5f06c4f39bf5ddac53a5c"
        },
        "date": 1793875556164,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 29104,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 70074.2,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 48889,
            "unit": "pkt/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Saikrishna Edupuganti",
            "username": "krsna1729",
            "email": "6157640+krsna1729@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "9fecafab7b3b0ecc30e5f06c4f39bf5ddac53a5c",
          "message": "ci(bench): chart a fixed trend plan that always finishes (#182)\n\nProblem: neither benchmark trend has moved since 2026-10-13.\n- Bench nightly charted throughput-matrix.plan (768 cells) only when it\n  finished inside a 5h box; it never did (about 510 cells, mio and tokio\n  only), so the chart step was skipped every night (6 of 6 checked).\n- Bench weekly ran breadth (~40 min), a 3h throughput box and a fixed\n  150-minute full-matrix slice: 370+ minutes against the 360-minute job\n  limit, so it was cancelled 3 weeks running before charting anything.\n\nChange:\n- New docs/plans/throughput-trend.plan: 48 cells (3 runtimes x 2 ingress\n  x 2 encryption x 200/1200 connections x 1/4 Mbit/s) with\n  throughput-matrix.plan's fixed baseline. Both workflows run it with no\n  time box and chart only it: every point is the same cells measured to\n  completion. Nightly runs 1 rep, weekly 3.\n- The exploratory runs (nightly throughput-matrix sweep, weekly\n  full-matrix slice) get the job time left, minus 20 minutes for the\n  report/chart/upload steps, instead of fixed boxes. They keep their TSV\n  artifacts and never chart.\n- The trend charts get fresh gh-pages series, dev/bench-nightly-trend and\n  dev/bench-weekly-trend: dev/bench-nightly holds three 2026-10 points\n  from throughput-matrix.plan under the same per-runtime names, and\n  mixing them would draw a false step.\n- Weekly no longer runs throughput-matrix.plan: it duplicated the nightly\n  exploration at the same rep count.\n\nEvidence:\n- Last completed nightly (run 41392028037): 508 throughput cells in 5h;\n  steps before the sweep take 16 minutes.\n- Local (this host, release srt-bench): throughput-trend.plan --reps 1\n  ran 48 cells (96 rows) in 1,807 s, exit 0; the github-benchmark report\n  gives one median pkt/s series per runtime (compio 12,094; mio 35,633;\n  tokio 22,937).",
          "timestamp": "2026-11-03T13:22:11Z",
          "url": "https://github.com/krsna1729/srt-rs/commit/9fecafab7b3b0ecc30e5f06c4f39bf5ddac53a5c"
        },
        "date": 1793961948098,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 30748.5,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 74281.6,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 47548.3,
            "unit": "pkt/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Saikrishna Edupuganti",
            "username": "krsna1729",
            "email": "6157640+krsna1729@users.noreply.github.com"
          },
          "committer": {
            "name": "Saikrishna Edupuganti",
            "username": "krsna1729",
            "email": "6157640+krsna1729@users.noreply.github.com"
          },
          "id": "91eeef82a2c0dd0e3f1263ab0a8e062af572d8d2",
          "message": "Record Robotweax rekey cause as unestablished\n\nThe interop record stated why Robotweax's encrypted callers fail as fact.\nThe trace shows only a post-connect same-index KMREQ with a new salt and\nSEK; whether Robotweax is reacting to this receiver's handshake KMRSP is\nnot established. Reword the risk item to the observation.\n\nEvidence: documentation only.",
          "timestamp": "2026-11-06T14:09:36Z",
          "url": "https://github.com/krsna1729/srt-rs/commit/91eeef82a2c0dd0e3f1263ab0a8e062af572d8d2"
        },
        "date": 1794048313938,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 25574.9,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 58762.6,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 39703.1,
            "unit": "pkt/s"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Saikrishna Edupuganti",
            "username": "krsna1729",
            "email": "6157640+krsna1729@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "5f5c566e9bff7c7c5ffabd1ca02365c876ece8f3",
          "message": "perf(protocol): bound receive-side work per datagram, tick and group poll (F01, F04, F09-F13) (#188)\n\n* test(protocol): count receive-side loop work in one WorkCounters snapshot\n\nProblem: the receiver's work bounds were measured by four ad-hoc counters\nthat disagreed on what they count. `receive_expected_sequence_scans`\ncounted scan invocations, not iterations; `loss_detection_steps` counted\nlogical gap positions, not operations; `delivery_time_checks` and the\nthread-local `LOSS_WORDS_TOUCHED` lived in different places, and nothing\ncounted packet-slot probes, successor lookups, loss enumeration, group\npending-key scans or released payloads. A per-entry-point bound could not\nbe stated, let alone asserted.\n\nChange: add `test_support::WorkCounters`, a scalar-only, thread-local\nsnapshot/reset of nine counters (packet-slot probes, bitmap data and\nsummary words, successor and deadline probes, loss entries visited,\nfrontier steps, group pending keys visited, released chunks). The\n`count_work!` macro increments them inside each loop iteration and\nexpands to nothing unless the crate is built for its own tests or with\n`test-support`. The four old counters are removed and their tests now\nread the snapshot; the classification-step asserts check `total_lost`,\nwhich is the same quantity.\n\nEvidence: `cargo test -p srt-proto -p pbt` passes; `cargo check -p\nsrt-proto` (no features) builds the counting sites away with no unused\nwarnings.\n\n* fix(protocol): classify a wide DATA gap in constant bitmap work (F11)\n\nProblem: `detect_losses` inserted the interval a far-ahead DATA exposes\nby walking one loss-bitmap data word, and updating one summary word, per\n64 positions. One DATA at base + W - 1 cost 2,049 bitmap words at the\n65,536-packet window. The existing test pinned that cost as its \"bound\"\n(1,024/1,025 data-word visits), so it protected nothing.\n\nChange: add `RangeBitset`, a three-level bitset (data words, per-block\nnonzero/full word masks with a kept population, and top-level block\nmasks). A mask bit is authoritative, so assigning a range rewrites at most\ntwo partial words, two partial blocks' masks and the top masks; covered\nwords and blocks keep stale contents until a point update reopens them.\nRange counts and next-set/next-clear searches are bounded the same way.\n`LossBitmap` now stores its circular window in one, so classifying,\nclearing or testing loss positions no longer depends on the gap width.\n\nEvidence: `wide_gap_classification_work_is_window_independent` measures\nthe bitmap words of one wide-gap receive at W = 32 / 8,192 / 65,536 with\nan aligned and an unaligned ISN against a limit of 32: before 3/4,\n257/258, 2,049/2,050 (failed); after 9/14, 13/18, 13/18. Reverting\nwhole-word assignment to a per-word loop fails it again (517 / 4,101).\n`RangeBitset` is checked against a model under random range and point\nupdates at capacities 64 to 65,536. Heap: 8,592 bytes at the maximum\nwindow (was 8,320), 1,088 at the default (budget 1,100).\n\n* fix(protocol): bound periodic NAK bitmap reads by the runs reported (F09)\n\nProblem: the periodic NAK's output cap did not bound its bitmap reads.\nAt most eight losses were collected through `iter()`, which reads every\ndata word; longer lists walked every word from the resume point through\nthe window, empty words included. One far loss cost 1,089 bitmap words at\nthe 65,536-packet window; nine sparse losses cost 1,610.\n\nChange: walk runs with `RangeBitset::next_one` / `next_zero`, which use the\nword and block masks to jump over empty and full stretches, so each\nreported run costs a constant number of word reads however far apart the\nruns are or however long one is. The eight-loss sort path and its\n`emit_sorted_runs` helper go: the run walk is already ordered.\n\nEvidence: `periodic_nak_bitmap_reads_scale_with_runs_not_window` checks\none far loss, nine sparse losses, one window-wide run and an alternating\nlist cut after 16 runs at W = 32 / 8,192 / 65,536 against 24 words per\nrun (+1). Before: far 3 / 193 / 1,089, sparse 6 / 267 / 1,610, dense\n6 / 129 / 1,025 (failed). After: far 16 / 19 / 20, sparse 62 / 104 /\n118, dense 14 / 8 / 8, alternating 101 / 108 / 108. Scanning word by word\nto the next run fails it again (603 at 65,536).\n\n* fix(protocol): derive the expected sequence after a head repair (F12)\n\nProblem: when expected DATA repaired a loss, `advance_expected_seq` probed\nthe packet window one position at a time through the retained suffix.\nReceiving 1..W-1 with future deadlines and then 0 cost W frontier steps\nand W + 3 slot probes (65,539 at the 65,536-packet window). It also\nstopped at any position that was neither a packet nor a loss, so a\nDROPREQ hole between two repaired losses pinned the ACK there for good.\n\nChange: the next expected sequence is the oldest loss, or the position\nafter the classification frontier when nothing is missing -- libsrt's\nfirst-loss-or-next ACK position (`getFirstNoncontSequence`). Both are\nconstant-work lookups now that the loss list answers `first()` from its\nmasks.\n\nEvidence: `filling_the_head_hole_does_not_scan_the_retained_suffix` at\nW = 32 / 8,192 / 65,536, limit 0 frontier steps and 8 slot probes:\nbefore 32 / 8,192 / 65,536 steps (failed), after 0 steps and 2 probes at\nevery window; restoring the probe loop fails it again.\n`dropped_positions_between_repaired_losses_do_not_pin_the_ack` pins the\nACK fix: the old loop left the ACK at 103, now 106.\n\n* fix(protocol): inspect only the head gap on a TLPKTDROP tick (F01)\n\nProblem: `drop_too_late`, run on every connected ACK tick, enumerated\nevery loss, and for each one looked up the retained successor and\ncomputed its deadline, then collected, removed and re-hashed the expired\npositions and stepped the expected sequence through them. One DATA a\nwindow ahead with a far-future timestamp left W - 1 losses that every\nnot-yet-due tick re-walked: 65,535 loss entries, successor lookups and\ndeadline evaluations per tick at the 65,536-packet window.\n\nChange: like libsrt's TSBPD loop (`CUDT::tsbpd` checks the first valid\npacket after the head gap, core.cpp:5673-5703), inspect only the head\ngap: one successor lookup and one deadline decide every loss in it, the\ngap goes in one range clear, and the walk stops at the first gap that is\nnot due. At most `MAX_EXPIRED_GAPS_PER_VISIT` (64) gaps go per call; the\nconnection continues a capped visit on the zero-delay `DeliveryContinue`\ntimer, so a due backlog is still given up at once rather than a tick\nlater. `drop_too_late` now returns the gaps as `LossRange`s, and the\nconnection's local sender reconciliation takes one call per gap\n(`discard_acked_within`, equivalent to the old per-sequence calls).\n\nFor monotone timestamps the gaps given up are the same as before; with\nnon-monotone timestamps a later gap whose successor is due no longer goes\nahead of an earlier one that is not, matching libsrt.\n\nEvidence: `tlpktdrop_tick_work_is_window_independent`, eight not-due\nticks at W = 32 / 8,192 / 65,536 (limit: no loss enumeration, one\nsuccessor, one deadline, 16 bitmap words): before 31 / 8,191 / 65,535\nentries, successors and deadlines per tick (failed); after 0 / 1 / 1 at\nevery window. `tlpktdrop_due_backlog_retires_in_bounded_visits` retires\nW/2 due gaps in 64-gap visits of bounded work, and\n`a_due_gap_backlog_is_given_up_in_continued_visits` checks the\nconnection continues them. Mutations -- per-loss successor/deadline\nenumeration, no per-visit cap, no continuation flag -- each fail one of\nthem.\n\n* fix(protocol): retire a DROPREQ's packets by page, release them in budgeted visits (F10)\n\nProblem: a DROPREQ cost O(range width) in the call that applied it. The\npacket window removed and freed every covered packet before returning,\nand the expected sequence was stepped one position at a time through the\ndropped interval. A valid full-window DROPREQ over a retained window\nfreed 65,536 packets and probed 67,585 slots in one call at the\n65,536-packet window; one over an empty interval at the expected\nsequence stepped the frontier 65,536 times.\n\nChange: the packet window keeps, per block of 64 pages, a mask of pages\nretired by a range removal, and one bit per block retired wholesale, next\nto the block's live count. `remove_range` removes the values of the at\nmost two partial pages at its ends at once, marks whole pages and blocks\nretired, and adjusts the live count from page occupancy and block counts:\nconstant work. Retired values are unreachable at once; their storage is\nreleased by `release_retired`, at most `MAX_RETIRED_RELEASED_PER_VISIT`\n(256) work units per call, from a cursor starting at the range. Inserting\ninto a retired page releases that page first. The receiver runs one\nvisit per DATA, drop and forced advance (`release_retired_packets`), the\nconnection one per ACK tick, so an idle receiver still frees the storage.\nAfter the drop the expected sequence is re-derived as the first loss or\nfrontier + 1. A retired range is cleared by slot, so the receiver clips a\nDROPREQ to the live packet span first (a range reaching back before the\nspan could otherwise alias a retained packet further on).\n\nThe window's idle heap grows by two mask words per block: 2,064 to\n2,096 bytes at the default window.\n\nEvidence: `wide_dropreq_work_per_visit_is_window_independent` (limit\n2 * 256 + 16 slot probes plus releases, 96 bitmap words, no frontier\nsteps), at W = 32 / 8,192 / 65,536: before, retained window 35+32 /\n8,449+8,192 / 67,585+65,536 slot probes plus releases, empty interval\n32 / 8,192 / 65,536 frontier steps (failed); after, retained 1+32 /\n10+252 / 24+252, empty 1 / 2 / 16 probes and no frontier steps; the\nrelease visits that follow stay within the same limit and finish in at\nmost W/192 + 1 visits. Mutations: releasing synchronously, stepping the\nexpected sequence, dropping the clip, leaving retired values reachable,\nreviving a page without releasing it, and removing the ACK-tick or\narrival release each fail a test (`a_dropreq_behind_the_span_spares_packets_sharing_its_slots`,\n`ack_ticks_release_packets_a_dropreq_removed`,\n`arriving_data_releases_dropped_packets`, and the packet-window proptest,\nwhich now bursts runs and releases partially).\n\n* fix(protocol): advance a lagging group member by range clear (F04)\n\nProblem: group delivery advances every member's receiver to the next\ngroup sequence on each delivered payload. `advance_expected_sequence`\ncollected every loss into a vector to find those below the target, so a\nmember lagging behind a wide gap -- one DATA a window ahead, W - 2 losses\n-- re-walked its whole loss list on every group poll: 65,534 loss\nentries and 1,159 bitmap words per delivered packet at the\n65,536-packet window, plus an allocation.\n\nChange: the F12 rule. The skipped losses go in one range clear from the\nexpected sequence, and the expected sequence becomes the first loss left\nor the frontier + 1 (at least the target). The forced advance also runs\none budgeted release visit for packets it retired. The loss list's\n`iter` is now test-only.\n\nEvidence: `forced_advance_work_is_window_independent`, worst of eight\none-step advances behind a W - 2 loss gap at W = 32 / 8,192 / 65,536\n(limit: no loss enumeration or frontier steps, 32 bitmap words): before\n31 / 8,190 / 65,534 loss entries and 8 / 263 / 1,159 words (failed);\nafter 0 entries and 8 words at every window. Restoring the enumeration\nfails it again.\n\n* fix(protocol): find the group's pending head and stale fragments by ordered lookup (F13)\n\nProblem: the group's receive side found its oldest pending payload by\nreducing over every pending key -- on every poll, every given-up-gap\ncheck and every owned-payload bound -- and delivering a multi-packet\nmessage probed each of its interior sequences for stale fragments. A\nbacklog of 65,536 pending payloads cost 65,535 key visits per head\nlookup; delivering one message spanning 65,536 packets cost 65,537.\n\nChange: pending sequences span less than half the sequence space, so the\noldest is the numerically first key unless a key lies half a space above\nit, in which case the span wraps and the first such key is oldest: two\nordered lookups. The interior of a delivered message is cleared by\nordered range (two across a wrap), visiting only keys that are present.\n`bound_group_owned_pending` uses the same head lookup.\n\nEvidence: `pending_head_and_fragment_delivery_work_is_backlog_independent`\n(wrapping backlog, limit 8 key visits) at 32 / 8,192 / 65,536: before\n31 / 8,191 / 65,535 head visits and 33 / 8,193 / 65,537 delivery visits\n(failed); after 2 and 4 at every size. Ignoring the wrap lookup returns\nthe wrong head (Some(0) instead of 2^31 - 4) and fails it.\n\n* test(protocol): compile the work counters into unit tests only\n\nProblem: `count_work!` expanded under `any(test, feature =\n\"test-support\")`. The crate's benches build the library through the\nself dev-dependency with `test-support`, so every Criterion run measured\nthe counter increments too -- not the production code.\n\nChange: the counters, `test_support::work` and `WorkCounters` exist only\nunder `cfg(test)`. No other target uses them; benches and dependents'\ntests (even with `test-support`) now run uncounted code, the same as a\nrelease build.\n\nEvidence: `cargo check -p srt-proto` and `--features\ntest-support,raw-codec` build without warnings, and the lib work-bound\ntests still count.\n\n* test(protocol): property-test that receive entry points do window-independent work\n\nAdds `receive_entry_points_do_window_independent_work`: 48 random\naction streams, each replayed at W = 32 / 8,192 / 65,536 from an initial\nsequence within 64 of the wrap. Actions are DATA arrivals up to a window\nahead with non-monotone timestamps, duplicates, DROPREQs reaching behind\nthe retained span, TLPKTDROP ticks, forced advances as a lagging group\nmember sees them, release visits and deliveries. Every call's\nWorkCounters delta must stay under the same limits at every window: 672\nslot probes plus releases, 66 successor and deadline probes, 1,584\nbitmap words, 2 frontier steps, no loss enumeration and no pending-key\nscan.\n\nRuntime: 0.09 s in a debug test build. Mutations caught: stepping the\nexpected sequence through a drop (3 frontier steps at W = 65,536 for a\n2-wide drop) and enumerating losses on a forced advance.\n\n* docs: describe the window-independent receive-side bounds\n\nDocuments the bounds from this PR: the loss bitmap, the expected-sequence\nrule, the TLPKTDROP head-gap rule and the drop_too_late return type, the\ndeferred DROPREQ release, and the group head lookup. Updates the loss\nbitmap's maximum footprint (8,592 bytes) in the owner contract and marks\nthe open drop_too_late/advance_expected_sequence note as superseded.\n\n* perf(protocol): read loss runs a word at a time and trim hot-path bookkeeping\n\nProblem: interleaved A/B Criterion runs against 207573d on vmi3423592\nshowed the periodic NAK walk taking 14.0 us -> 48.5 us on an\nalternating-loss window: two descents through the bitset's summary levels\nper one-packet run. They also showed the in-order receive/pop path slower.\n\nChange: `for_each_run_segment` descends once per nonzero data word and\ntakes every run inside the word with bit operations, following a run\nthat reaches the word's end with `next_zero`. `RangeBitset::set` updates\nits one word directly instead of going through the range assignment.\nThe packet window keeps each block's three mask words adjacent (no\ndivide by three to index them), skips the retired-page check on insert\nand successor search when nothing is retired, and marks its point\noperations `#[inline]`.\n\nEvidence (median of 3 interleaved rounds, before -> after): periodic NAK\nalternating 14.07 -> 19.07 us (was 48.5), dense 650 -> 77 ns, one loss\n170 -> 69 ns. In-order receive/pop is still slower: healthy_in_order/1\n99.9 -> 114.9 ns, tsbpd zero_loss buffered 1.30 -> 1.45 ms (see the PR\nfor the full table). Work-bound tests are unchanged and pass.\n\n* perf(protocol): keep DROPREQ retirement bookkeeping off the in-order path\n\nProblem: the receive-side work bounds cost the ordinary in-order steady\nstate 10-25% (healthy_in_order/1 97.8 -> 116.2 ns, /30 2.68 -> 3.20 us,\nTSBPD drain-per-packet 1.46 -> 1.71 ms). Bisected with interleaved\nCriterion runs and with `perf stat -e instructions` over a deterministic\nreceive+pop driver (instructions per packet, in-order / TSBPD drain):\n\n  207573d base           715 / 851\n  7aeab3e F11 bitset     790 / 990\n  257c250 F09            745 / 899\n  39818f2 F01            747 / 904\n  a4688ad F10 retire     873 / 1062   <- the step (Criterion: +17..23%)\n  006d878 head           872 / 1053\n\nCauses, on the in-order path:\n- F10: insert tested `has_retired() || retired_blocks != 0` and every\n  point insert/remove kept a second counter (`stored`); the grown window\n  ops pushed `Page::remove` out of line, so pop took its value back\n  through memory. The receive path also ran a release visit per packet.\n- F11: LossBitmap contains/remove/first no longer short-circuited on an\n  empty loss list, as the lazily allocated bitmap they replaced did.\n\nChange:\n- The packet window counts `retired_held` (retired values awaiting\n  release) instead of `stored`; inserting or removing a live value never\n  touches it. When it reaches zero the wholesale block marks are dropped\n  (`settle_retired`; per-page marks already clear as pages empty), so\n  \"nothing retired\" is one test and insert no longer checks\n  `retired_blocks`.\n- `revive_page` and `Page::demote` are cold; `Page::remove` is always\n  inlined. The successor search skips the retired filter when nothing is\n  retired. `release_retired_packets` tests `has_retired()` first.\n- LossBitmap contains/remove/first return at once on an empty loss list.\n\nNo bound changes: retirement, release budgets and the work counters are\nas before.\n\nEvidence: interleaved Criterion medians, 4 rounds rotating binary order,\nbase 207573d / head 006d878 / this change, vmi3423592 (6 vCPU KVM),\n`taskset -c 3 <bench> --bench <case> --warm-up-time 1\n--measurement-time 3`:\n\n  healthy_in_order/1           97.8 ns / 116.2 (+18.8%) / 100.4 (+2.6%)\n  healthy_in_order/30          2.68 us / 3.20 (+19.2%) / 2.77 (+3.1%)\n  healthy_in_order/1000        100.6 us / 109.8 (+9.2%) / 101.3 (+0.7%)\n  tsbpd zero_loss_empty        1.49 ms / 1.41 / 1.29 (noise)\n  tsbpd zero_loss_250ms_buf    1.42 ms / 1.60 (+12.9%) / 1.42 (-0.2%)\n  tsbpd 250ms_drain_per_pkt    1.46 ms / 1.71 (+17.2%) / 1.57 (+8.2%)\n  drop_range max_legal/dense   14.6 us / 1.23 / 1.22\n  drop_range max_legal/mixed   956 us / 823 / 896\n  full_window_gap/65536        10.5 us / 7.27 / 7.51\n  periodic_nak dense_loss      570 ns / 73.3 / 71.3\n  periodic_nak alternating     13.7 us / 18.1 / 17.8 (unchanged by this)\n\nDriver instructions per packet: in-order 715.6 / 871.6 / 764.6, TSBPD\ndrain 850.5 / 1052.9 / 917.7; cycles (median of 7 alternating runs):\nin-order 341.3 / 389.3 / 341.5, TSBPD drain 326.4 / 394.4 / 347.4.\nWhat remains is inherent to retiring by mark: the per-block live counts\nthat let a whole 64-page block retire in O(1) (~25 instructions per\npacket) and the reachability test on get/remove (~16).\n\n`cargo test -p srt-proto -p pbt --all-features`, including the work-bound\ntests and `receive_entry_points_do_window_independent_work`, and\n`RUSTFLAGS=-Zsanitizer=address cargo +nightly test -p srt-proto\n--all-targets --target x86_64-unknown-linux-gnu` pass.\n\n* chore: untrack Criterion output committed under crates/srt-protocol/target\n\nProblem: 006d878 committed 432 Criterion result files from a stray\ncrates/srt-protocol/target/criterion directory; .gitignore only ignored\nthe workspace-root /target.\n\nChange: drop them from the index (the files stay on disk) and ignore\ntarget/ at any depth.",
          "timestamp": "2026-11-08T10:19:06Z",
          "url": "https://github.com/krsna1729/srt-rs/commit/5f5c566e9bff7c7c5ffabd1ca02365c876ece8f3"
        },
        "date": 1794134724710,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 30499.4,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 75501.8,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 48009.5,
            "unit": "pkt/s"
          }
        ]
      }
    ]
  }
}