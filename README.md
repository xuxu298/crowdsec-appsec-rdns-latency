# crowdsec-appsec-rdns-latency

A runnable procedure for measuring one number that does not appear to have been published
anywhere:

> When PTR lookups are slow or return SERVFAIL, how much **in-band** latency does the
> `crowdsecurity/rdns` postoverflow add to a CrowdSec AppSec decision, and does it breach
> `APPSEC_PROCESS_TIMEOUT` (default `1000ms`)?

## Status: NOT RUN

**We have not run this measurement.** There is not a single measured number in this
repository. `RESULTS.md` is deliberately empty, and it stays empty until somebody runs the
procedure and fills it in.

We are publishing the procedure instead of the result because we do not have a v1.8.0 AppSec
deployment to measure. We could have read the v1.8.0 source and written down what we think it
does. That would be a reading, not a measurement, and the entire point of this repository is
that those two things are not interchangeable. Reading the tag tells you what the code
intends. Only running it tells you what the latency is.

If you run this and get a number, the number is yours. Open a PR against `RESULTS.md`, or
publish it wherever you like.

## Why the number is worth having

AppSec is in-band. The remediation component holds the live request while CrowdSec decides,
and the decision has a budget: `APPSEC_PROCESS_TIMEOUT`, default `1000ms`.

The `crowdsecurity/rdns` postoverflow performs a reverse DNS lookup. CrowdSec's DNS cache
uses a lookup timeout of `3s`. Three seconds is larger than one second. So a single cold PTR
lookup against a slow or broken resolver can, in principle, consume the whole in-band budget
and overrun it.

Whether it *actually* does depends on where the lookup sits relative to the in-band path and
on how the cache behaves under real traffic. That is a question about a running system. It is
settled by a stopwatch, not by reading `run.go`.

The question is not ours. Operators running AppSec at scale raised it, and at least one
reported removing the `rdns` postoverflow outright as a workaround, in
<https://github.com/crowdsecurity/crowdsec/issues/4600>. What is missing from that thread, and
from everywhere else we looked, is a number.

## What is measured, and what is deliberately not

Measured: **the wall-clock latency of the AppSec decision, as seen by the remediation
component.** The harness speaks the AppSec protocol directly to the AppSec listener, exactly
the way a bouncer does, and times that one call.

Not measured: the origin application's response time. That number includes the origin, the
network, and the proxy, and it will move for reasons that have nothing to do with `rdns`. If
you time the wrong clock you will get a plausible-looking number that answers a different
question.

## The trap that will make this measurement lie to you

CrowdSec's DNS cache is an LRU with a TTL. **The first request from a given IP pays for the
PTR lookup. Every request after it, within the TTL, does not.**

So the obvious harness -- hammer the endpoint a thousand times from one source IP -- measures
one cold lookup and 999 cache hits, reports a low p99, and tells you everything is fine. It is
the cheapest possible way to get a confident wrong answer here.

`measure.sh` therefore uses a **fresh source IP for every single request** by default. If you
change that, you are no longer measuring the thing this repository is about.

## Controls

A latency number on its own does not establish that `rdns` caused it. Run all three legs, in
the same session, on the same host:

| leg | resolver | `rdns` postoverflow | what it establishes |
|---|---|---|---|
| **A. baseline** | fast | removed | the harness and the host are not themselves slow |
| **B. positive control** | fast | installed | `rdns` is on the path and costs something measurable |
| **C. the measurement** | slow / SERVFAIL | installed | what a degraded resolver does to the in-band budget |

Leg A is not optional. If leg A already shows latency near `1000ms`, the harness is measuring
your own machine and legs B and C mean nothing.

If leg C is slow but leg B is identical to leg A, `rdns` is not on your in-band path and the
result does not generalise to a deployment where it is.

## Running it

Requirements: `bash`, `curl`, `awk`, `sort`, `python3`, and a CrowdSec host with the AppSec
acquisition configured and a bouncer API key you can use.

```sh
# 1. Start the controllable PTR responder (leg C). It answers with a fixed delay,
#    or SERVFAIL, so the failure mode is reproducible rather than borrowed from
#    whatever your upstream resolver happens to be doing today.
sudo python3 slow-ptr.py --listen 127.0.0.1:5353 --delay-ms 2500

# 2. Point the CrowdSec host's resolver at it, and restart crowdsec so the change
#    is picked up. Revert this when you are done.

# 3. Run the harness.
./measure.sh \
  --appsec-url http://127.0.0.1:7422/ \
  --api-key    "$BOUNCER_KEY" \
  --requests   200 \
  --label      "leg-C-slow-ptr"
```

`measure.sh` writes a per-request CSV to `out/<label>.csv` and prints a summary.

## Reading the result

The summary prints six numbers. Read them in this order:

1. **`n_ok`** -- how many requests actually got an AppSec verdict. If this is not equal to
   `--requests`, stop. You measured errors, not latency, and the percentiles below are
   computed over a set you did not intend.
2. **`p50_ms`** -- the typical request. This is what your users feel most of the time.
3. **`p95_ms`, `p99_ms`** -- the tail. In-band latency is a tail problem. A p50 of 4ms with a
   p99 of 1400ms is not a fast system; it is a system that stalls one request in a hundred.
4. **`max_ms`** -- the worst single decision observed.
5. **`n_over_budget`** -- requests whose decision took longer than `APPSEC_PROCESS_TIMEOUT`.
   **This is the headline number.** Zero means the budget held under the conditions you
   created. Non-zero means it did not, and the count over `n_ok` is your breach rate.

A single run is one sample of one configuration on one host. Two runs that disagree are more
informative than one run that looks tidy, so run each leg at least twice and record both.

## Scope, stated plainly

- Not run by us. No number here is measured; there are no numbers here.
- **No interpreter has ever parsed these two files.** We could not run `bash -n` or
  `py_compile` in the environment they were written in, so we cannot tell you the scripts are
  even syntactically valid, let alone correct. They were reviewed by eye and nothing more. We
  are saying so rather than letting "published" stand in for "checked" -- if the first thing
  `measure.sh` does on your machine is throw a syntax error, that is a defect we shipped, and
  a PR fixing it is welcome.
- The fixture resolver is synthetic. It reproduces "slow" and "SERVFAIL" deliberately, which
  is the point -- it is not a capture of anyone's production DNS.
- Tested against no versions, because it has not been run. The protocol headers it sends are
  the documented AppSec ones; if they change, this harness breaks loudly rather than quietly.
- No third-party review. Nobody has checked this but us, and we have not run it.

## Licence

MIT. Take it, change it, publish the number.
