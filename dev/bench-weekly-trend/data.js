window.BENCHMARK_DATA = {
  "lastUpdate": 1793711968979,
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
        "date": 1793711968541,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "compio",
            "value": 24405,
            "unit": "pkt/s"
          },
          {
            "name": "mio",
            "value": 61372.8,
            "unit": "pkt/s"
          },
          {
            "name": "tokio",
            "value": 39709.5,
            "unit": "pkt/s"
          }
        ]
      }
    ]
  }
}