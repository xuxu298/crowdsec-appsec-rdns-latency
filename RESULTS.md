# Results

**Empty on purpose.** Nobody has run the procedure in this repository yet, including the
people who wrote it. Every cell below is blank because a blank cell is honest and a guess is
not.

If you run it, fill in a row and open a PR. Partial rows are welcome; a run of leg A alone is
worth more than nothing, and a run that failed is worth reporting too.

## What a row has to carry

A latency number with no conditions attached cannot be checked by anyone, which makes it
decoration rather than evidence. So each row records the conditions alongside the number.

| field | why it is here |
|---|---|
| `date` | the software moves; a number without a date rots silently |
| `crowdsec version` | the whole question is about v1.8.0 versus earlier |
| `leg` | A baseline, B positive control, or C the measurement -- see README |
| `resolver` | fast, or the fixture with its delay and mode |
| `rdns` | postoverflow installed or removed. This is the variable under test |
| `requests` | sample size |
| `fresh IPs` | yes or no. If no, the cache absorbed the lookups and the row measures little |
| `p50 / p95 / p99 / max` | in-band decision latency, ms |
| `n_over_budget` | decisions slower than `APPSEC_PROCESS_TIMEOUT`. The headline |
| `budget` | the timeout value actually configured, ms |
| `n_ok` | if this is below `requests`, the percentiles cover survivors only |
| `host` | CPU, RAM, and whether anything else was running |

## Runs

| date | crowdsec | leg | resolver | rdns | requests | fresh IPs | p50 | p95 | p99 | max | n_over_budget | budget | n_ok | host |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| | | | | | | | | | | | | | | |

## Reading a filled table

Compare **within a host, within a session**. Two rows from two different machines differ for
reasons that have nothing to do with `rdns`, and comparing them will produce a confident
answer to a question nobody asked.

The comparison that carries the argument is B against C on the same host: same binary, same
harness, same sample size, one variable changed. If C breaches the budget and B does not, the
degraded resolver is the cause. If both breach, the cause is upstream of the resolver. If
neither breaches, say so plainly -- a measurement that finds nothing is still a measurement,
and it is the one result nobody bothers to publish.

## Known ways this table could still be wrong

- **Leg A never run.** Without a baseline the numbers describe the host as much as the
  software, and there is no way to tell which.
- **`--same-ip` left on.** The DNS cache serves the second request onward, the tail collapses,
  and the run reports that everything is fine. See README, "The trap".
- **One run per leg.** A single sample cannot distinguish a real effect from a noisy host. Two
  runs that disagree are more informative than one that looks tidy.
- **Timing the wrong clock.** `measure.sh` times the AppSec decision. If you instead time your
  origin application's response, you get a plausible number for a different quantity.
- **Sample too small for the tail.** `n_over_budget` is a tail statistic. At `--requests 20`,
  a p99 does not exist in any meaningful sense, whatever the script prints.
