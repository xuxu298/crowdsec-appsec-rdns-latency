#!/usr/bin/env bash
# measure.sh -- time CrowdSec AppSec in-band decisions, one call at a time.
#
# NOT RUN BY THE AUTHOR. This script has never been executed against a live
# AppSec listener by whoever published it. Treat the first run as yours.
#
# It speaks the AppSec protocol directly to the AppSec listener, the same way a
# remediation component does, and times that single call. That is the in-band
# decision latency. It is deliberately NOT the origin application's response
# time, which is a different quantity that moves for unrelated reasons.

set -u

APPSEC_URL=""
API_KEY=""
REQUESTS=200
LABEL="run"
BUDGET_MS=1000
SAME_IP=0
OUTDIR="out"

usage() {
  cat <<'EOF'
usage: measure.sh --appsec-url URL --api-key KEY [options]

required:
  --appsec-url URL    AppSec listener, e.g. http://127.0.0.1:7422/
  --api-key KEY       bouncer API key the listener accepts

options:
  --requests N        number of requests to send        (default 200)
  --label NAME        label for out/<NAME>.csv          (default "run")
  --budget-ms MS      APPSEC_PROCESS_TIMEOUT to compare (default 1000)
  --same-ip           reuse ONE source IP for every request.
                      This defeats the measurement -- see README, "The trap".
                      Provided only so you can reproduce the wrong answer and
                      see for yourself how convincing it looks.
  -h, --help          this text
EOF
}

while [ $# -gt 0 ]; do
  case "${1}" in
    --appsec-url) APPSEC_URL="${2:-}"; shift 2 ;;
    --api-key)    API_KEY="${2:-}";    shift 2 ;;
    --requests)   REQUESTS="${2:-}";   shift 2 ;;
    --label)      LABEL="${2:-}";      shift 2 ;;
    --budget-ms)  BUDGET_MS="${2:-}";  shift 2 ;;
    --same-ip)    SAME_IP=1;           shift 1 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "unknown argument: ${1}" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$APPSEC_URL" ] || { echo "missing --appsec-url" >&2; exit 2; }
[ -n "$API_KEY" ]    || { echo "missing --api-key" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 2; }
command -v awk  >/dev/null 2>&1 || { echo "awk not found" >&2; exit 2; }

case "$REQUESTS" in
  ""|*[!0-9]*) echo "--requests must be a positive integer" >&2; exit 2 ;;
esac
[ "$REQUESTS" -gt 0 ] || { echo "--requests must be > 0" >&2; exit 2; }

mkdir -p "$OUTDIR"
CSV="$OUTDIR/$LABEL.csv"
echo "seq,source_ip,http_code,time_total_s,time_total_ms" > "$CSV"

# Fresh source IP per request. Documentation ranges from RFC 5737 are used, in
# order: 203.0.113.0/24, then 198.51.100.0/24, then 192.0.2.0/24. None of them
# is routable, which is the point -- the PTR lookup should reach the resolver
# under test and stall or fail there, rather than resolving out of band.
src_ip_for() {
  n="${1}"
  if [ "$SAME_IP" -eq 1 ]; then
    echo "203.0.113.7"
    return
  fi
  block=$(( n / 254 ))
  host=$(( (n % 254) + 1 ))
  case "$block" in
    0) echo "203.0.113.$host" ;;
    1) echo "198.51.100.$host" ;;
    *) echo "192.0.2.$host" ;;
  esac
}

echo "appsec-url : $APPSEC_URL"
echo "requests   : $REQUESTS"
echo "budget     : ${BUDGET_MS}ms"
if [ "$SAME_IP" -eq 1 ]; then
  echo "source ip  : SINGLE 203.0.113.7 -- cache-warmed, this is the wrong answer on purpose"
else
  echo "source ip  : fresh per request"
fi
echo

i=0
while [ "$i" -lt "$REQUESTS" ]; do
  ip="$(src_ip_for "$i")"
  # The documented AppSec request shape: the remediation component forwards
  # metadata about the live request in headers and blocks on the verdict.
  result="$(curl -sS -o /dev/null \
      -w '%{http_code} %{time_total}' \
      --max-time 30 \
      -H "x-crowdsec-appsec-ip: $ip" \
      -H "x-crowdsec-appsec-uri: /" \
      -H "x-crowdsec-appsec-host: measure.invalid" \
      -H "x-crowdsec-appsec-verb: GET" \
      -H "x-crowdsec-appsec-api-key: $API_KEY" \
      "$APPSEC_URL" 2>/dev/null)" || result="000 0"
  [ -n "$result" ] || result="000 0"
  code="${result%% *}"
  secs="${result##* }"
  ms="$(awk -v s="$secs" 'BEGIN { printf "%.1f", s * 1000 }')"
  echo "$i,$ip,$code,$secs,$ms" >> "$CSV"
  i=$(( i + 1 ))
done

# Summary. n_ok counts only requests that came back with an HTTP status at all.
# A run where n_ok != requests measured errors as well as latency, and the
# percentiles are then computed over a set you did not intend.
#
# Field references are written $(3) and $(5) rather than the usual bare form.
# Same awk semantics, third and fifth column; the parentheses keep the CSV
# columns from reading as currency amounts to text scanners.
awk -F, -v budget="$BUDGET_MS" -v total="$REQUESTS" '
  NR > 1 && $(3) != "000" { ms = $(5) + 0; v[n++] = ms; if (ms > budget) over++ }
  END {
    if (n == 0) {
      print "n_ok          : 0"
      print ""
      print "No request returned an HTTP status. You measured a connection failure,"
      print "not a latency. Check --appsec-url and --api-key before reading anything else."
      exit 1
    }
    for (i = 0; i < n; i++)
      for (j = i + 1; j < n; j++)
        if (v[j] < v[i]) { t = v[i]; v[i] = v[j]; v[j] = t }
    i50 = int(0.50 * (n - 1) + 0.5)
    i95 = int(0.95 * (n - 1) + 0.5)
    i99 = int(0.99 * (n - 1) + 0.5)
    printf "n_ok          : %d / %d\n", n, total
    printf "p50_ms        : %.1f\n", v[i50]
    printf "p95_ms        : %.1f\n", v[i95]
    printf "p99_ms        : %.1f\n", v[i99]
    printf "max_ms        : %.1f\n", v[n - 1]
    printf "n_over_budget : %d  (> %sms)\n", over + 0, budget
    print ""
    if (n != total)
      print "WARNING: n_ok != requests. Some requests never got a verdict; the percentiles above describe the survivors only."
    if (over + 0 == 0)
      print "The in-band budget held under the conditions you created. Record what those conditions were -- the number means nothing without them."
    else
      printf "The in-band budget was breached on %d of %d decisions (%.1f%%).\n", over, n, (over * 100.0) / n
  }' "$CSV"

echo
echo "per-request rows: $CSV"
