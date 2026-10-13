window.BENCHMARK_DATA = {
  "lastUpdate": 1791877273398,
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
      }
    ]
  }
}