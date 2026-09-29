# Phishing Email Analyzer

A Python-based project for analyzing suspicious email files in `.eml` format and assigning a phishing risk score based on common indicators of malicious email activity.

This project is designed as a practical security utility for learning, testing, and experimentation. It helps identify red flags such as suspicious senders, urgent language, malicious-looking domains, URL obfuscation, SPF/DKIM/DMARC failures, and suspicious keywords.

## Project Overview

The analyzer reads an email message, parses key fields, extracts URLs, inspects headers, and calculates a risk score out of 100. If the score exceeds a set threshold, the email is flagged as suspicious.

This project is useful for:

- examining suspicious email samples
- learning how phishing emails are structured
- detecting common phishing indicators
- building a foundation for a larger email-security tool

## Features

- Parse `.eml` email files
- Extract sender and subject information
- Inspect email headers
- Extract URLs and domains from the message body
- Detect URL obfuscation and suspicious patterns
- Check for suspicious keywords and urgency cues
- Evaluate authentication metadata such as SPF, DKIM, and DMARC
- Detect file attachments and compute SHA-256 hashes
- Produce a phishing risk score and suspicious/not-suspicious result

## Demo / Sample Email

The repository includes a sample suspicious email file:

- `sample_email.eml`

This file can be used to test the analyzer immediately without needing to create your own email sample first.

## Project Structure

```text
Cyber Security/
├── main.py
├── README.md
├── requirements.txt
├── sample_email.eml
├── tests/
│   └── test_phishing_analyzer.py
├── phishing_email_analyzer/
│   ├── __init__.py
│   ├── analyzer.py
│   └── cli.py
└── .gitignore
```

## Requirements

This project uses the Python standard library only, so there are no external dependencies required for the base version.

## Setup

1. Clone the repository:

```bash
git clone https://github.com/your-username/phishing-email-analyzer.git
cd phishing-email-analyzer
```

2. Create and activate a virtual environment (optional but recommended):

```bash
python -m venv .venv
```

On Windows:

```bash
.venv\Scripts\activate
```

On macOS/Linux:

```bash
source .venv/bin/activate
```

3. Run the project:

```bash
python main.py sample_email.eml
```

## How to Use

### Analyze a sample email

```bash
python main.py sample_email.eml
```

### Analyze your own `.eml` file

```bash
python main.py path/to/your_email.eml
```

### Run the test suite

```bash
python -m unittest discover -s tests -q
```

## Example Output

The analyzer prints a JSON result like this:

```json
{
  "file": "sample_email.eml",
  "sender": "security-alert@banking-update.com",
  "subject": "Urgent: Verify Your Account",
  "urls": [
    "http://verify-bank-login.example-security-check.com/reset.php?token=abc123"
  ],
  "domains": [
    "verify-bank-login.example-security-check.com"
  ],
  "suspicious_keywords": [
    "urgent",
    "verify",
    "security",
    "account",
    "login"
  ],
  "risk_score": 93,
  "is_suspicious": true
}
```

## Risk Scoring Logic

The project uses heuristic scoring based on common phishing patterns such as:

- urgent or threatening language
- requests to verify credentials or accounts
- suspicious sender domains
- login or security-themed URLs
- authentication failures (SPF/DKIM/DMARC)
- brand impersonation indicators
- suspicious or obfuscated URLs

The score is capped at 100, and emails with a score above 50 are considered suspicious.

## Limitations

This project is a starter implementation and relies on local heuristics rather than live threat intelligence or third-party reputation services. It is intended for educational and security-analysis use, not as a complete production-grade phishing detection system.

## Use Cases

- Security analyst testing
- Phishing awareness training
- Email triage experiments
- Building a foundation for a larger email security project

## Future Enhancements

Possible improvements for a more advanced version include:

- real-time malicious URL reputation checks
- better header validation for authentication results
- support for bulk email analysis
- CSV/JSON report export
- GUI application for easier use
- machine learning-based classification

## License

This project is intended for educational and personal use. Add a license if you plan to publish it publicly on GitHub.

Example:

```bash
MIT License
```

## Contributing

Contributions are welcome. If you want to extend the project, you can:

1. fork the repository
2. create a feature branch
3. add tests for your changes
4. submit a pull request

## Author / Contact

You can update this section with your name, GitHub profile, and project details before publishing.

```text
Author: Your Name
GitHub: https://github.com/your-username
Email: your-email@example.com
```

## Summary

This project provides a solid beginner-friendly phishing email analyzer that demonstrates how to parse `.eml` files, extract relevant email data, and score suspicious messages using practical heuristics. It is a strong starting point for a GitHub project because it is easy to understand, easy to run, and simple to extend.
