from __future__ import annotations

import argparse
import json
from pathlib import Path

from phishing_email_analyzer import analyze_email


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze suspicious email files for phishing indicators.")
    parser.add_argument("email_path", help="Path to the .eml file to analyze")
    args = parser.parse_args()

    result = analyze_email(Path(args.email_path))
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
