# Threat-Enriched IDS: Project Workflow

## Project goal

Suricata detects network events and writes them to its EVE JSON log. A Python service reads alert events, preserves the original alert, selects valid public IP addresses, avoids unnecessary repeat lookups, and checks cached reputation data. Cache misses can now be queried through AbuseIPDB and VirusTotal when API keys are configured. The service will later produce a prioritized assessment with an explanation. Firewall blocking is an optional lab extension, not a requirement for the core pipeline.

## Current implementation

The parser, public-IP filtering, duplicate-lookup tracking, SQLite TTL cache, and asynchronous API clients have working prototypes. API requests have been tested offline with simulated provider responses; live requests still require the user's own API keys. Threat scoring, metrics, and live Suricata integration are future work. The current program does not yet produce final threat priorities.

## Phase plan and completion checks

### Phase 1: Alert parser

**Work:** Read EVE log lines individually, parse each line as JSON, and keep events whose `event_type` is `alert`. Extract the timestamp, source and destination IPs, alert signature, and severity for downstream processing.

**Completion check:** The sample EVE file produces two alert records, and its DNS event is ignored. The parser can process the sample from the beginning of the file.

**Status: Done.**

### Phase 2: IP filtering and deduplication

**Work:** Validate both source and destination IPs. Only valid public addresses are candidates for external reputation lookup; private, reserved, or malformed addresses must not be sent to providers. Track whether a public IP was recently looked up so repeated alerts do not trigger redundant requests. Deduplication applies to lookups, not alerts: every alert remains available for reporting and scoring.

**Completion check:** Public addresses are accepted, private and invalid addresses are rejected, and a repeated IP is identified without dropping its alert.

**Status: Prototype done.**

### Phase 3: SQLite cache

**Work:** Store provider results using the IP and provider as the record key, with an expiration time (TTL). Query the cache before making a provider request. A valid cached result is a hit; a missing or expired result is a miss. Cache data must remain available across program restarts.

**Completion check:** A stored result can be read back, remains available after reopening the cache, and becomes a miss after its TTL expires. The main workflow can distinguish cache hits from misses.

**Status: Prototype done.**

### Phase 4: Asynchronous API clients

**Work:** Implement separate clients for AbuseIPDB and VirusTotal using the agreed interface and normalized result format. Query both providers concurrently when their results are not cached. Handle network timeouts, provider errors, and rate limits independently so one provider failing does not block the other. Cache only successful, usable responses. Allow a failed lookup to be retried instead of marking it as successfully deduplicated.

**Completion check:** Both providers return usable normalized data; one provider's failure does not stop the other; repeated alerts reuse cached results; and a failed request can be retried. Keep API keys outside source control using environment variables such as `ABUSEIPDB_API_KEY` and `VIRUSTOTAL_API_KEY`.

**Status: Implemented and tested offline; live key-based validation remains.**

### Phase 5: Threat scoring

**Work:** Combine the IDS alert severity with whatever provider intelligence is available. Define clear rules for Low, Medium, and High priority and include a human-readable reason. Treat missing or failed provider data as unknown, not as evidence that an IP is safe.

**Completion check:** The same input evidence always produces the same priority and explanation; missing data is represented explicitly.

**Status: Pending.**

### Phase 6: Logging and metrics

**Work:** Save assessment records and collect alert count, filtered IP count, duplicate lookups, cache hits and misses, API errors, and processing time. Keep enough information to reproduce and discuss an evaluation run.

**Completion check:** Results and measurements can be exported or summarized for the evaluation report, and the measurements distinguish cold-cache from warm-cache runs.

**Status: Pending.**

### Phase 7: Optional firewall blocking

**Work:** In an isolated Ubuntu lab, test proposed `iptables` actions only after the core enrichment workflow is stable. Start in a log-only or dry-run mode; do not automatically block traffic during early testing.

**Completion check:** Each proposed action is recorded with its reason and can be reviewed. This phase is optional and should not delay the core system.

**Status: Optional.**

### Phase 8: Real Suricata integration

**Work:** Run the Python service in an environment where it can read Suricata's actual EVE log on the Ubuntu VM. Generate controlled test traffic that produces known alerts and verify the full path.

**Completion check:** Controlled traffic produces a Suricata alert, the Python service enriches it, and a prioritized result is visible end to end.

**Status: Pending.**

## Recommended order and evaluation

Finish Phase 4 first, then implement scoring and metrics, and then connect the service to real Suricata. Work on firewall blocking only after the core system runs reliably. The project proposal names both team members but does not assign phases to you or Caleb; agree on ownership before splitting Phase 4 and Suricata integration.

For the final evaluation, compare cold-cache and warm-cache runs, measure API lookup and total processing time, and use independently labeled cases to evaluate prioritization and false positives. The final deliverables are the code, evaluation report, and presentation.

## Project structure

- `src/main.py` - command-line entry point and monitoring workflow
- `src/parser.py` - EVE JSON line parsing and alert extraction
- `src/ip_filter.py` - validation and selection of public IPs
- `src/dedup.py` - recent-IP tracking to suppress repeated lookups
- `src/cache.py` - SQLite TTL cache for provider results
- `src/api_clients.py` - asynchronous AbuseIPDB and VirusTotal lookups
- `tests/sample_eve.json` - sample EVE data for local validation
- `tests/test_api_clients.py` - offline API, concurrency, and retry checks
- `logs/eve.json` - intended path for a real or runtime EVE log

## Input and expected output

The sample input is `tests/sample_eve.json`. It includes alert entries and a non-alert DNS event to check that the parser only processes alerts. `logs/eve.json` is the intended input path when demonstrating with a real or runtime log; sample validation does not require a live Suricata installation.

Current alert output is printed in a form similar to:

```text
ALERT src=1.2.3.4 sig=ET SCAN Potential SSH Scan
```

Lookup results are printed and cached, but threat priority output belongs to the scoring phase.

## Running the project

From the project root, install the HTTP client dependency into your activated virtual environment:

```powershell
python -m pip install -r requirements.txt
```

Preview the lookups without keys or external requests:

```powershell
python -m src.main --log tests/sample_eve.json --from-start --dry-run
```

To perform real lookups, set your own keys in the current PowerShell session and omit `--dry-run`:

```powershell
$env:ABUSEIPDB_API_KEY = "your-abuseipdb-key"
$env:VIRUSTOTAL_API_KEY = "your-virustotal-key"
python -m src.main --log tests/sample_eve.json --from-start
```

Do not commit API keys or paste them into issues or logs. If a key is missing, that provider is skipped; the other provider can still run. A successful result is cached for one hour. HTTP errors, rate limits, invalid responses, and timeouts are reported without caching and can be retried by a later alert. The service uses a ten-second request timeout. The old sample cache may contain manually inserted demonstration results; remove `data/reputation_cache.sqlite3` before a clean live run.

Run against the real log path when that file contains events:

```powershell
python -m src.main --log logs/eve.json --from-start
```

`--from-start` tells the monitor to process the existing contents from the beginning rather than only waiting for newly appended log lines. The process then waits for new lines; stop it with Ctrl+C. Without `--from-start`, it waits for newly appended lines immediately.

Run the offline checks without API keys:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

## Local validation results

### Parser and startup

Command:

```powershell
python -m src.main --log tests/sample_eve.json --from-start
```

Result: starts without relative-import errors; the sample contains two alert events and a DNS event that is skipped.

### Public IP filtering

Command:

```powershell
python -c "from src.ip_filter import get_public_ip; print(get_public_ip('1.2.3.4')); print(get_public_ip('10.0.0.5')); print(get_public_ip('invalid'))"
```

Observed output:

```text
1.2.3.4
None
None
```

Result: public IP accepted; private and invalid values rejected.

### SQLite cache hit and expiry

Command:

```powershell
python -c "import time; from src.cache import ReputationCache; c=ReputationCache(); c.put('1.2.3.4', 'expiry_demo', {'score': 42}, ttl_seconds=1); print('immediate:', c.get('1.2.3.4', 'expiry_demo')); time.sleep(1.2); print('after expiry:', c.get('1.2.3.4', 'expiry_demo')); c.close()"
```

Observed output:

```text
immediate: {'score': 42}
after expiry: None
```

Result: the cached value is available before expiry and returns a miss after its TTL.

### Combined Phase 2 and Phase 3 validation

Command:

```powershell
python -c "from src.ip_filter import get_public_ip; from src.cache import ReputationCache; import time; print(get_public_ip('1.2.3.4')); print(get_public_ip('10.0.0.5')); print(get_public_ip('invalid')); c=ReputationCache('data/phase23_check.sqlite3'); c.put('1.2.3.4','abuseipdb',{'score':42},ttl_seconds=1); print(c.get('1.2.3.4','abuseipdb')); time.sleep(1.2); print(c.get('1.2.3.4','abuseipdb')); c.close()"
```

Observed output:

```text
1.2.3.4
None
None
{'score': 42}
None
```

Result: public IP filtering and cache storage/expiry work together as expected.

### Deduplication demo

Command:

```powershell
python -m src.main --log tests/dedup_demo.json --from-start --dry-run
```

Observed lookup behavior:

```text
CACHE MISS
NEW lookup needed
DUPLICATE lookup
```

Result: uncached IP/provider pairs are identified for lookup and a repeated pair is recognized as a duplicate without dropping its alert. If the local cache already holds a result, it is shown as `CACHE HIT` instead.

