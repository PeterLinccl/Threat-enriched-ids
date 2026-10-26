# Threat-Enriched IDS: Project Workflow

## Our project goal

We are building a service that reads Suricata EVE JSON alerts and enriches public IP addresses with reputation data. We filter invalid and non-public IPs, avoid unnecessary repeated lookups, and use a SQLite cache. When a result is not cached, we query AbuseIPDB and VirusTotal. Next, we will combine the alert and reputation results into a threat priority with an explanation. Firewall blocking is an optional lab extension.

## What we have built

We have implemented the alert parser, public-IP filtering, lookup deduplication, SQLite TTL cache, and asynchronous AbuseIPDB and VirusTotal clients. Three offline tests passed, and both providers returned results during live checks with our sample alerts. We have not yet implemented threat scoring, logging and metrics, or integration with a real Suricata log.

## Phase plan and completion checks

### Phase 1: Alert parser

**Work:** We read EVE log lines individually, parse each line as JSON, and keep events whose `event_type` is `alert`. We extract the timestamp, source and destination IPs, alert signature, and severity for later processing.

**Completion check:** Our sample EVE file produces two alert records, while its DNS event is ignored. We can process the sample from the beginning of the file.

**Status: Done.**

### Phase 2: IP filtering and deduplication

**Work:** We validate both source and destination IPs. We only consider valid public addresses for external reputation lookups. We track recent lookups so repeated alerts do not trigger unnecessary requests. We still display every alert, including repeated ones.

**Completion check:** We accept public addresses, reject private and invalid addresses, and identify repeated lookup attempts without dropping their alerts.

**Status: Prototype done.**

### Phase 3: SQLite cache

**Work:** We store provider results using the IP and provider as the record key, with an expiration time (TTL). We check the cache before making a provider request. A valid result is a cache hit; a missing or expired result is a cache miss. Cache data remains available across program restarts.

**Completion check:** We can read a stored result after reopening the cache, and the result becomes a miss after its TTL expires. Our main workflow distinguishes cache hits from misses.

**Status: Prototype done.**

### Phase 4: Asynchronous API clients

**Work:** We query AbuseIPDB and VirusTotal for uncached public IPs. For each alert, we run eligible provider requests concurrently and normalize their responses. We handle failures independently: a successful response is cached, while a failed lookup can be retried on a later alert. We keep API keys outside the source code.

**Completion check:** Both providers return usable results; one provider's failure does not stop the other; repeated alerts reuse cached results; and failed requests can be retried.

**Status: Done. Three offline tests and live API lookups with sample alerts passed.**

### Phase 5: Threat scoring

**Work:** We will combine IDS alert severity with the provider data that is available. We will define Low, Medium, and High priority rules and include a readable reason. We will treat missing or failed provider data as unknown rather than as evidence that an IP is safe.

**Completion check:** The same evidence produces the same priority and explanation, and missing data is represented explicitly.

**Status: Pending.**

### Phase 6: Logging and metrics

**Work:** We will save assessment records and measure alert count, filtered IP count, duplicate lookups, cache hits and misses, API errors, and processing time.

**Completion check:** We can export or summarize the results for our evaluation report and compare cold-cache with warm-cache runs.

**Status: Pending.**

### Phase 7: Optional firewall blocking

**Work:** If time permits, we will test proposed `iptables` actions in an isolated Ubuntu lab after the core enrichment workflow is stable. We will begin in a log-only or dry-run mode.

**Completion check:** Each proposed action has a recorded reason and can be reviewed. This phase is optional.

**Status: Optional.**

### Phase 8: Real Suricata integration

**Work:** We will run our Python service where it can read a real Suricata EVE log. We will generate controlled traffic that produces known alerts and verify the complete workflow.

**Completion check:** Controlled traffic produces a Suricata alert, our service enriches it, and we can see a prioritized result end to end.

**Status: Pending.**

## Our next steps and evaluation

We will implement threat scoring, then logging and metrics, and then connect the service to a real Suricata log. Firewall blocking remains optional. My teammate and I will coordinate ownership of the remaining implementation and evaluation work.

For the final evaluation, we plan to compare cold-cache and warm-cache runs, measure API lookup and total processing time, and use independently labeled cases to evaluate prioritization and false positives. Our final deliverables are the code, evaluation report, and presentation.

## Project structure

- `src/main.py` — command-line entry point and monitoring workflow
- `src/parser.py` — EVE JSON line parsing and alert extraction
- `src/ip_filter.py` — validation and selection of public IPs
- `src/dedup.py` — recent lookup tracking
- `src/cache.py` — SQLite TTL cache for provider results
- `src/api_clients.py` — asynchronous AbuseIPDB and VirusTotal requests
- `requirements.txt` — Python dependencies
- `tests/sample_eve.json` — sample EVE data for local validation
- `tests/dedup_demo.json` — repeated alerts for the deduplication demo
- `tests/test_api_clients.py` — offline tests for both API clients
- `tests/test_pipeline.py` — offline cache and failed-lookup retry test
- `logs/eve.json` — planned path for a real or runtime EVE log

## Input and current output

We use `tests/sample_eve.json` for local checks. It contains two alert events and one DNS event; we ignore the DNS event. We will use `logs/eve.json` when a real or runtime EVE log is available.

Our current output shows each alert, cache hits and misses, and successful or failed provider lookups. For example:

```text
ALERT src=1.2.3.4 sig=ET SCAN Potential SSH Scan
  CACHE HIT: 1.2.3.4 / abuseipdb
  CACHE MISS: 1.2.3.4 / virustotal
  LOOKUP OK: 1.2.3.4 / virustotal
```

The cache status depends on earlier runs. We will add the final threat priority and explanation in Phase 5.

## Running our project

We run commands from the project root with the virtual environment activated. First, we install the dependencies:

```powershell
python -m pip install -r requirements.txt
```

We create a local `.env` file in the project root and replace these examples with our own API keys:

```text
ABUSEIPDB_API_KEY=your-own-key
VIRUSTOTAL_API_KEY=your-own-key
```

Git ignores `.env`. We do not put real keys in source files or this README.

To preview lookup decisions without sending API requests, we run:

```powershell
python -m src.main --log tests/dedup_demo.json --from-start --dry-run
```

To process sample alerts and query providers when results are not cached, we run:

```powershell
python -m src.main --log tests/sample_eve.json --from-start
```

When a real Suricata EVE log is available at the planned location, we will run:

```powershell
python -m src.main --log logs/eve.json
```

`--from-start` processes existing log lines before waiting for new ones. Without it, our program waits for newly added lines. We press Ctrl+C to stop it. A cached result appears as `CACHE HIT` and does not trigger another API request.

We run the offline tests with:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

## Local validation results

### Parser and startup

Command:

```powershell
python -m src.main --log tests/sample_eve.json --from-start --dry-run
```

Result: our program starts without relative-import errors. It processes two alert events and skips the DNS event. Dry-run mode does not send API requests.

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

Result: we accept the public IP and reject the private and invalid values.

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

Result: we can retrieve the cached value before expiry; after expiry, we get a cache miss.

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

Result: public IP filtering and cache storage and expiry work together as expected.

### Deduplication demo

Command:

```powershell
python -m src.main --log tests/dedup_demo.json --from-start --dry-run
```

Result: for an uncached IP/provider pair, the first alert shows `NEW lookup needed` and the repeated alert shows `DUPLICATE lookup`. If we already have a cached result, our program shows `CACHE HIT` instead. We still see both alerts.

### Phase 4: API clients and pipeline

Command:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Result: all three offline tests passed. We tested both provider response formats and verified that a failed provider can be retried without repeating a successful lookup.

We also ran `tests/sample_eve.json` with our locally configured API keys. AbuseIPDB and VirusTotal returned usable results for `1.2.3.4` and `8.8.8.8`. Later runs showed cache hits. Provider reputation values can change, so we do not treat the observed values as fixed expected results. We have not yet tested this workflow against a real Suricata log.