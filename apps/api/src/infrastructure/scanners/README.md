# Scanner author notes

A scanner implements `supports(context)` and `run(context, reporter, signal)`.

- Report progress on a real unit of work: files read, packages queried, batches finished.
- Call `progress` at least every couple of seconds. That updates the scan heartbeat.
- Do not call `progress(1)`. The orchestrator marks the stage complete when `run` resolves.
- Check `signal.aborted` between units of work and throw if it is aborted.
- You may call `reporter.finding()` while you work. Still return the full array.
- A thrown error fails that stage only. Fetch, triage, and the global timeout fail the scan.
- Never execute repository files, and never log a raw secret. Mask it first.
