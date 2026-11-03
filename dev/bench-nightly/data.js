window.BENCHMARK_DATA = {
  "lastUpdate": 1793691456137,
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
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "f442deb7185821698f04385ffb7a78f96ca7c331",
          "message": "test(kani): rung 4 — DenseSlotArena Socket-ID proofs (#143)\n\n* test(kani): rung 4 — DenseSlotArena Socket-ID proofs\n\nThree Kani proofs (0.68.0) over `DenseSlotArena`, run by a new CI job\nthat fails unless all KANI_PROOFS=3 verify and every cover is reached:\n\n- any 3 allocations and removals (oldest or newest live session),\n  max_slots 1: every issued Socket ID resolves exactly while its session\n  lives, IDs are distinct, len never exceeds max_slots (348 s);\n- one session at a time through every slot until slot 0 returns at a new\n  generation: no earlier ID resolves again, all IDs distinct (21 s);\n- a preferred ID is honored for a never-used slot, refused after its\n  session ends, and the old ID never resolves (23 s).\n\nMutations, each a counterexample: take_slot not advancing the generation;\nthe preferred path ignoring slot_used; `len > max_slots` admission.\nmax_slots is 1 below a 2-slot floor so the max_slots check, not an empty\nfree list, refuses the second session (at 2 the mutant survived).\n\nKani builds use a 2-slot routing floor (`MIN_ROUTE_SLOTS`) instead of\n64: the logic is the same, and CBMC runs out of memory modelling 64\nslots and their free list even for a concrete trace. `RandomState::new`\nis stubbed (Kani cannot read the OS random source the `lent` set seeds\nfrom). The symbolic proof keeps IDs concrete per choice: a symbolic\npreferred ID makes CBMC model a free-list removal at a symbolic index,\nwhich did not finish in 40 minutes.\n\n* review: honest Kani coverage wording; preferred slot reuse traced; cover guard fails on no input\n\n- README and module docs: the symbolic proof covers any 3 allocations and\n  removals; slot reuse (5 steps with the FIFO free list) and the\n  preferred-ID path are concrete traces.\n- The preferred-ID trace now cycles until the preferred slot is allocated\n  again and checks its new ID differs and the preferred ID never resolves\n  (53 s; still fails when the preferred path ignores slot_used).\n- The CI cover guard also fails when no cover summary is reported.",
          "timestamp": "2026-10-08T15:32:03Z",
          "url": "https://github.com/krsna1729/srt-rs/commit/f442deb7185821698f04385ffb7a78f96ca7c331"
        },
        "date": 1791780656916,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 31918,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 56300.4,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 56421.7,
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
          "id": "f442deb7185821698f04385ffb7a78f96ca7c331",
          "message": "test(kani): rung 4 — DenseSlotArena Socket-ID proofs (#143)\n\n* test(kani): rung 4 — DenseSlotArena Socket-ID proofs\n\nThree Kani proofs (0.68.0) over `DenseSlotArena`, run by a new CI job\nthat fails unless all KANI_PROOFS=3 verify and every cover is reached:\n\n- any 3 allocations and removals (oldest or newest live session),\n  max_slots 1: every issued Socket ID resolves exactly while its session\n  lives, IDs are distinct, len never exceeds max_slots (348 s);\n- one session at a time through every slot until slot 0 returns at a new\n  generation: no earlier ID resolves again, all IDs distinct (21 s);\n- a preferred ID is honored for a never-used slot, refused after its\n  session ends, and the old ID never resolves (23 s).\n\nMutations, each a counterexample: take_slot not advancing the generation;\nthe preferred path ignoring slot_used; `len > max_slots` admission.\nmax_slots is 1 below a 2-slot floor so the max_slots check, not an empty\nfree list, refuses the second session (at 2 the mutant survived).\n\nKani builds use a 2-slot routing floor (`MIN_ROUTE_SLOTS`) instead of\n64: the logic is the same, and CBMC runs out of memory modelling 64\nslots and their free list even for a concrete trace. `RandomState::new`\nis stubbed (Kani cannot read the OS random source the `lent` set seeds\nfrom). The symbolic proof keeps IDs concrete per choice: a symbolic\npreferred ID makes CBMC model a free-list removal at a symbolic index,\nwhich did not finish in 40 minutes.\n\n* review: honest Kani coverage wording; preferred slot reuse traced; cover guard fails on no input\n\n- README and module docs: the symbolic proof covers any 3 allocations and\n  removals; slot reuse (5 steps with the FIFO free list) and the\n  preferred-ID path are concrete traces.\n- The preferred-ID trace now cycles until the preferred slot is allocated\n  again and checks its new ID differs and the preferred ID never resolves\n  (53 s; still fails when the preferred path ignores slot_used).\n- The CI cover guard also fails when no cover summary is reported.",
          "timestamp": "2026-10-08T15:32:03Z",
          "url": "https://github.com/krsna1729/srt-rs/commit/f442deb7185821698f04385ffb7a78f96ca7c331"
        },
        "date": 1791791877430,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 22162.2,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 41640.1,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 37679.1,
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
          "id": "f442deb7185821698f04385ffb7a78f96ca7c331",
          "message": "test(kani): rung 4 — DenseSlotArena Socket-ID proofs (#143)\n\n* test(kani): rung 4 — DenseSlotArena Socket-ID proofs\n\nThree Kani proofs (0.68.0) over `DenseSlotArena`, run by a new CI job\nthat fails unless all KANI_PROOFS=3 verify and every cover is reached:\n\n- any 3 allocations and removals (oldest or newest live session),\n  max_slots 1: every issued Socket ID resolves exactly while its session\n  lives, IDs are distinct, len never exceeds max_slots (348 s);\n- one session at a time through every slot until slot 0 returns at a new\n  generation: no earlier ID resolves again, all IDs distinct (21 s);\n- a preferred ID is honored for a never-used slot, refused after its\n  session ends, and the old ID never resolves (23 s).\n\nMutations, each a counterexample: take_slot not advancing the generation;\nthe preferred path ignoring slot_used; `len > max_slots` admission.\nmax_slots is 1 below a 2-slot floor so the max_slots check, not an empty\nfree list, refuses the second session (at 2 the mutant survived).\n\nKani builds use a 2-slot routing floor (`MIN_ROUTE_SLOTS`) instead of\n64: the logic is the same, and CBMC runs out of memory modelling 64\nslots and their free list even for a concrete trace. `RandomState::new`\nis stubbed (Kani cannot read the OS random source the `lent` set seeds\nfrom). The symbolic proof keeps IDs concrete per choice: a symbolic\npreferred ID makes CBMC model a free-list removal at a symbolic index,\nwhich did not finish in 40 minutes.\n\n* review: honest Kani coverage wording; preferred slot reuse traced; cover guard fails on no input\n\n- README and module docs: the symbolic proof covers any 3 allocations and\n  removals; slot reuse (5 steps with the FIFO free list) and the\n  preferred-ID path are concrete traces.\n- The preferred-ID trace now cycles until the preferred slot is allocated\n  again and checks its new ID differs and the preferred ID never resolves\n  (53 s; still fails when the preferred path ignores slot_used).\n- The CI cover guard also fails when no cover summary is reported.",
          "timestamp": "2026-10-08T15:32:03Z",
          "url": "https://github.com/krsna1729/srt-rs/commit/f442deb7185821698f04385ffb7a78f96ca7c331"
        },
        "date": 1791877272788,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 27947.1,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 52747.1,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 53194,
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
          "id": "cae714ec6f7ab88f183671c95e911738df1d3254",
          "message": "ci(bench): chart a fixed trend plan that always finishes\n\nProblem: neither benchmark trend has moved since 2026-10-13.\n- Bench nightly charted throughput-matrix.plan (768 cells) only when it\n  finished inside a 5h box; it never did (about 510 cells, mio and tokio\n  only), so the chart step was skipped every night (6 of 6 checked).\n- Bench weekly ran breadth (~40 min), a 3h throughput box and a fixed\n  150-minute full-matrix slice: 370+ minutes against the 360-minute job\n  limit, so it was cancelled 3 weeks running before charting anything.\n\nChange:\n- New docs/plans/throughput-trend.plan: 48 cells (3 runtimes x 2 ingress\n  x 2 encryption x 200/1200 connections x 1/4 Mbit/s) with\n  throughput-matrix.plan's fixed baseline. Both workflows run it with no\n  time box and chart only it: every point is the same cells measured to\n  completion. Nightly runs 1 rep, weekly 3.\n- The exploratory runs (nightly throughput-matrix sweep, weekly\n  full-matrix slice) get the job time left, minus 20 minutes for the\n  report/chart/upload steps, instead of fixed boxes. They keep their TSV\n  artifacts and never chart.\n- The trend charts get fresh gh-pages series, dev/bench-nightly-trend and\n  dev/bench-weekly-trend: dev/bench-nightly holds three 2026-10 points\n  from throughput-matrix.plan under the same per-runtime names, and\n  mixing them would draw a false step.\n- Weekly no longer runs throughput-matrix.plan: it duplicated the nightly\n  exploration at the same rep count.\n\nEvidence:\n- Last completed nightly (run 41392028037): 508 throughput cells in 5h;\n  steps before the sweep take 16 minutes.\n- Local (this host, release srt-bench): throughput-trend.plan --reps 1\n  ran 48 cells (96 rows) in 1,807 s, exit 0; the github-benchmark report\n  gives one median pkt/s series per runtime (compio 12,094; mio 35,633;\n  tokio 22,937).",
          "timestamp": "2026-11-03T06:14:21Z",
          "url": "https://github.com/krsna1729/srt-rs/commit/cae714ec6f7ab88f183671c95e911738df1d3254"
        },
        "date": 1793691455226,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 34621.6,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 85158.5,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 53658,
            "unit": "pkt/s"
          }
        ]
      }
    ]
  }
}