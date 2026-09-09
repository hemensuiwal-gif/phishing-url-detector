# Phishing URL Detector

A beginner-friendly Flask web application that analyzes a URL for common phishing indicators. It is designed for defensive cybersecurity education, awareness training, and a college project demonstration.

> **Important:** This tool provides a URL-risk assessment based on visible URL characteristics. It cannot guarantee that a URL is safe or malicious. A legitimate-looking URL can still lead to a dangerous website, and a suspicious-looking URL is not automatically malicious.

## Features

- Modern responsive homepage and results dashboard.
- Validates empty, incomplete, oversized, and malformed URLs.
- Checks HTTPS usage, URL length, IP-address hosts, subdomains, `@` symbols, hyphens, numbers, suspicious keywords, unusual structure, and common URL shorteners.
- Shows a transparent score, classification, meter, and explanation for every check.
- Performs local URL parsing only. The app does not visit submitted websites, follow redirects, collect credentials, or call threat-intelligence APIs.
- Includes security-awareness tips, safe presentation examples, tests, and GitHub-ready project files.

## Technologies

- Python 3.10+
- Flask 3
- HTML5, CSS3, and vanilla JavaScript
- Python standard library: `urllib.parse`, `ipaddress`, and `re`

## How Detection Works

The analyzer parses the URL locally and assigns points to observable warning signals:

| Check | Warning points |
| --- | ---: |
| HTTP instead of HTTPS | 15 |
| Numeric IP address as host | 25 |
| URL longer than 120 characters | 10 |
| Three or more subdomains | 10 |
| `@` symbol or embedded credentials | 20 |
| Three or more hyphens | 10 |
| Four or more numbers in hostname | 5 |
| Suspicious keyword matches | 5 each, capped at 15 |
| Unusual port, credentials, or path structure | 10 |
| Common URL shortener | 10 |

The total is capped at 100 so it is easy to explain during a presentation.

- **0-30:** Likely Safe
- **31-60:** Suspicious
- **61-100:** Potential Phishing

These thresholds are educational heuristics, not a threat-intelligence verdict. HTTPS is a positive signal for encrypted transport, but it does not prove that a site is trustworthy.

## Project Structure

```text
phishing-url-detector/
├── app.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
├── detector/
│   ├── __init__.py
│   └── analyzer.py
├── templates/
│   ├── index.html
│   └── result.html
├── static/
│   ├── css/style.css
│   └── js/script.js
├── tests/
│   └── test_analyzer.py
└── screenshots/README.md
```

## Installation on Windows

Open PowerShell in the project directory:

```powershell
cd "C:\path\to\phishing url detector"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use Command Prompt instead:

```bat
.venv\Scripts\activate.bat
```

No API keys, passwords, or external services are required. `.env.example` is included as a placeholder for future configuration.

## Run the Application

```powershell
python app.py
```

Open `http://127.0.0.1:5000` in a browser. Stop the development server with `Ctrl+C`.

For a production deployment, use a production WSGI server and configure the environment securely. Flask debug mode is used only to make local student development convenient.

## Test the Project

Install the optional test dependency if it is not already available:

```powershell
pip install pytest
pytest -q
```

A quick analyzer-only check also works without pytest:

```powershell
python -c "from detector import analyze_url; print(analyze_url('https://example.com'))"
```

Safe examples for a presentation include `https://example.com` and `https://www.python.org`. The warning-heavy test input uses the documentation-only IP range `198.51.100.24`; it is synthetic and should not be opened.

## GitHub Setup

1. Create a new empty repository on GitHub named `phishing-url-detector`. Do not add another README, `.gitignore`, or license because this project already contains them.
2. In PowerShell, from the project folder, run:

```powershell
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin YOUR_GITHUB_REPOSITORY_URL
git push -u origin main
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your repository URL, for example `https://github.com/your-username/phishing-url-detector.git`. Replace `your-username` with your GitHub username. Never commit passwords, API keys, tokens, or private URLs.

To publish later updates:

```powershell
git add .
git commit -m "Update project"
git push
```

## 3-5 Minute Presentation Flow

1. **Introduce the problem:** Phishing often relies on deceptive links and human trust. This project offers a local, explainable first-pass URL review.
2. **Show the homepage:** Explain that no website is visited and no credentials are collected.
3. **Enter `https://example.com`:** Point out the HTTPS, named host, short URL, and low score.
4. **Enter a safe synthetic warning example:** Use `http://198.51.100.24/login-verify-account-123` and explain that an IP host, HTTP, keywords, hyphens, and numbers add points. Do not open it.
5. **Explain the pipeline:** Flask receives the form, `detector/analyzer.py` parses the URL, checks features, sums capped points, and renders the result template.
6. **Explain the limitation:** This is not a blacklist, browser sandbox, reputation database, or guarantee. Real security decisions need additional trusted controls.

## Viva Questions and Short Answers

**Why is HTTPS not enough?** HTTPS encrypts traffic but does not prove the site owner is honest; phishing sites can also use HTTPS.

**Why use an IP address as a warning?** It can make a destination harder to recognize, although legitimate infrastructure sometimes uses IP addresses.

**Why separate `analyzer.py` from `app.py`?** Separation keeps web routing independent from testable detection logic.

**What does the score mean?** It is a transparent heuristic from URL structure, not a probability or a definitive maliciousness label.

**Does the application visit the submitted URL?** No. It only parses the text locally, which reduces privacy and safety concerns.

**Why cap the score at 100?** A fixed range makes the meter and thresholds easy to communicate.

**What are false positives?** A legitimate URL may contain warning-like features, so users should treat results as a review prompt rather than proof.

## Limitations

- It cannot inspect page content, redirects, certificates, DNS, domain age, reputation, or malware behavior.
- It may flag legitimate URLs with long paths, many subdomains, or security-related words.
- URL shorteners hide the destination and therefore deserve caution, but are not automatically malicious.
- The keyword list and thresholds are intentionally small and educational.
- URL parsing alone cannot establish intent or ownership.

## Future Improvements

These are ideas for future versions, not features currently implemented:

- Larger, versioned URL feature sets and a calibrated machine-learning classifier.
- Domain reputation checks and threat-intelligence APIs.
- A maintained database of known malicious URLs.
- Certificate, DNS, redirect-chain, and domain-age analysis with careful privacy controls.
- Browser extension integration.
- More advanced visualizations and exportable reports.

## Ethical and Security Disclaimer

This project is intended only for defensive cybersecurity education and awareness. Use it with URLs you are authorized to examine. It does not create phishing pages, collect passwords, bypass security, attack websites, or guarantee safety. Do not test random websites without permission.

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for the full text. The license permits reuse and modification with attribution and includes no warranty.
