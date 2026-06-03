---
name: llm-recon-automation
description: LLM-powered recon automation pipeline — single command full recon + JS analysis pipeline using AI CLI agents
category: recon
---

# LLM-Powered Recon Automation

> One command to run full recon: subfinder → httpx → waybackurls → gau → katana → nuclei → JS secrets analysis.

## The Pipeline
```
Input: "do recon on target.com"

1.  Recon Layer
    subfinder → httpx → waybackurls → gau → katana → nuclei

2.  JS Analysis Pipeline
    Extract JS → Fetch with UA → jsecrets scan → Grep secrets → Extract URLs

3.  Organized Output
    _recon/    → subfinder, httpx, waybackurls, nuclei results
    _jsrecon/  → js_files.txt, all_js_content.js, jsecrets_all.txt,
                 potential_secrets.txt, extracted_urls.txt
```

## Full Recon Chain
```bash
mkdir -p _recon _jsrecon

# Step 1: Subdomain discovery
subfinder -d $TARGET -silent -o _recon/subfinder.txt

# Step 2: Filter live hosts
cat _recon/subfinder.txt | httpx -silent -o _recon/httpx.txt

# Step 3: URL collection
cat _recon/httpx.txt | waybackurls | tee -a _recon/waybackurls.txt
gau $TARGET >> _recon/waybackurls.txt
katana -u $TARGET -silent -o _recon/katana.txt

# Step 4: Nuclei scan
nuclei -l _recon/httpx.txt -t ~/nuclei-templates/ -silent -o _recon/nuclei.txt

# Step 5: JS analysis
cat _recon/waybackurls.txt _recon/katana.txt 2>/dev/null | \
  grep -E '\.js$|\.js\?' | sort -u > _jsrecon/js_files.txt

while read jsurl; do
  curl -sL "$jsurl" -H "User-Agent: Mozilla/5.0" --max-time 10
done < _jsrecon/js_files.txt > _jsrecon/all_js_content.js 2>/dev/null

cat _jsrecon/all_js_content.js | jsecrets -i - > _jsrecon/jsecrets_all.txt 2>/dev/null
cat _jsrecon/all_js_content.js | grep -iE \
  "(api.key|token|secret|password|endpoint|bucket|s3|aws|auth|bearer)" | \
  sort -u > _jsrecon/potential_secrets.txt
cat _jsrecon/all_js_content.js | grep -Eo 'https?://[a-zA-Z0-9./_-]+' | \
  sort -u > _jsrecon/extracted_urls.txt
```

## LLM CLI Configuration
Configure your AI CLI to treat `"do recon on TARGET"` as a full recon trigger:

```bash
# Save as Gemini CLI config (~/.gemini/GEMINI.md or Claude project config):
When user says "do recon on <target>", execute:
1. mkdir -p _recon _jsrecon
2. subfinder -d <target> → httpx → waybackurls → gau → katana → nuclei
3. JS analysis: extract → fetch → scan → grep → extract
4. Present organized summary of findings
```

## Output Structure
```
_recon/
├── subfinder.txt     # All discovered subdomains
├── httpx.txt         # Live hosts
├── waybackurls.txt   # Historical URLs
├── katana.txt        # Crawled URLs
└── nuclei.txt        # Vulnerability matches

_jsrecon/
├── js_files.txt          # All JS URLs
├── all_js_content.js     # Aggregated JS content
├── jsecrets_all.txt      # jsecrets scan results
├── potential_secrets.txt # Grepped secrets/tokens
└── extracted_urls.txt    # URLs found in JS
```
