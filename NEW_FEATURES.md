# New Features

These additions are intended only for systems for which you have written authorization. The mass scanner enforces bounded CIDR/target counts and concurrency; the dashboard binds to localhost by default; and Nuclei is invoked without a shell.

## Live dashboard

From the project directory:

```bash
python 0xhunter.py dashboard --host 127.0.0.1 --port 8787
```

Open `http://127.0.0.1:8787/`. The dashboard submits an explicitly confirmed scan job and polls `/api/scans` for status, phase, progress, and finding count. The current progress callbacks are phase-level (`crawling`, `core modules`, `full modules`, `finalizing`, and `complete`).

## Mass scan and ASN inventory

Create an authorized target file, one URL or host per line:

```bash
python 0xhunter.py mass-scan --targets-file authorized_targets.txt --confirm --output mass_results.json
```

For one authorized CIDR, use a deliberately bounded range:

```bash
python 0xhunter.py mass-scan --cidr 192.0.2.0/28 --max-hosts 32 --confirm --output cidr_results.json
```

For domains, create `authorized_domains.txt` and run:

```bash
python 0xhunter.py mass-scan --domains-file authorized_domains.txt --confirm --output domain_results.json
```

For passive ASN prefix discovery, provide an ASN. The implementation retrieves announced prefixes from the RIPE Stat endpoint, limits the number of prefixes, then applies the mass-scan host cap:

```bash
python 0xhunter.py mass-scan --asn AS13335 --max-hosts 64 --confirm --output asn_results.json
```

Use a written scope allowlist before operating this feature. Do not use an entire company ASN unless the owner has explicitly authorized the relevant IP space and the resulting host count is understood.

## Nuclei templates

Install the Nuclei binary separately and place/update templates locally. Create `authorized_targets.txt` with one absolute HTTP(S) URL per line:

```bash
python 0xhunter.py nuclei \
  --targets-file authorized_targets.txt \
  --templates ./nuclei-templates \
  --severity info,low,medium,high,critical \
  --concurrency 10 \
  --rate-limit 50 \
  --confirm \
  --output nuclei_results.jsonl
```

The adapter uses `-list`, `-jsonl`, bounded concurrency, a rate limit, and zero retries by default. It does not download templates automatically and does not invoke a shell command. Template acquisition and updates should be performed separately after review.

## Files added or changed

| File | Purpose |
|---|---|
| `dashboard_server.py` | Local HTTP dashboard and in-memory scan-job store |
| `mass_scan.py` | Bounded target, domain, and CIDR probing |
| `asn_scan.py` | Passive ASN announced-prefix lookup |
| `nuclei_integration.py` | Safe Nuclei subprocess adapter and JSONL parser |
| `core/scanner.py` | Optional phase progress callback support |
| `0xhunter.py` | `dashboard`, `mass-scan`, and `nuclei` commands |
