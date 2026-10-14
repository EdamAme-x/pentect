# Live defense and usability benchmark (2026-10-14)

This is a paired end-to-end measurement, not a claim that Pentect catches every
secret. The same synthetic task was run through OpenCode directly and through
Pentect. Both arms used the real OpenRouter API and `openai/gpt-4.1-mini`; a
loopback relay checked each outbound request before forwarding it. The relay
recorded counts and statuses, not request bodies or credentials.

Environment: Windows, OpenCode 1.19.0, Pentect 0.0.95. Three paired trials per
scenario, each with a new client home, project, and generated synthetic secret.
The pair order alternated. No provider-failed pair was discarded in this run.

| Scenario | Direct: secret sent / trials | Pentect: secret sent / trials | Direct: task completed | Pentect: task completed | Median seconds direct / Pentect |
| --- | ---: | ---: | ---: | ---: | ---: |
| Secret in user prompt | 3/3 | 0/3 | 3/3 | 3/3 | 3.735 / 4.594 |
| Read `.env`, copy value locally | 3/3 | 0/3 | 3/3 | 2/3 | 7.390 / 7.891 |
| Print a log containing a bearer token | 3/3 | 0/3 | 3/3 | 3/3 | 5.906 / 7.891 |
| Write a benign file (control) | N/A | N/A | 3/3 | 3/3 | 5.250 / 6.407 |

"Secret sent" means the exact synthetic secret appeared in at least one HTTP
request body at the relay. Repeated requests in one run count once in the table.
"Task completed" requires the requested final marker and, for file tasks, the
exact local file contents. The elapsed time includes client startup, model
latency, tools, and gateway overhead; it does not isolate Pentect CPU cost.

The failed Pentect file trial reached the model and completed local read/write
tools, but the destination did not contain the exact requested value. It did
not contain the secret or a Pentect handle either. This is an observed utility
failure; the present value-free trace does not establish its root cause. In
other exploratory runs the model wrote the `TEST_TOKEN=` label as well as the
value. The benchmark deliberately scores such outputs as failures.

## Reproduce

Use an isolated test key and synthetic data. From the repository root:

```sh
python tools/benchmark_live_defense.py \
  --pentect /path/to/pentect \
  --opencode /path/to/opencode \
  --key-env OPENROUTER_API_KEY \
  --trials 3 \
  --report /path/outside/repo/report.json
```

The runner also accepts `--auth-file` pointing to an OpenCode auth JSON file.
The real API key stays in the benchmark process and is not passed to OpenCode
or Pentect. Each pair is retried if either provider arm fails; the report
records discarded and incomplete pairs. Exit code 2 indicates an incomplete
measurement. The report contains no secret values, request bodies, or client
transcripts. The temporary projects and logs are deleted after the run.

Limitations: three trials and one model/client/OS are too small for a general
success-rate claim. Exact-string observation does not test transformed,
encoded, image-only, or partial leaks. The control has no secret to defend.
The real model can vary between runs, and OpenRouter may change the model
behind the route. This benchmark is intended to be repeated across clients,
models, platforms, and harder secret formats before presentation as a product
level claim.
