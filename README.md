# Cyber Log Threat Detector

A beginner-friendly defensive cybersecurity project that parses SSH authentication logs and flags patterns that may indicate brute-force login attempts.

## Features
- Detects failed login attempts, invalid-user attempts, and successful logins.
- Counts failed attempts by source IP and username.
- Flags repeated failures above a configurable threshold.
- Highlights IPs associated with both failed and successful logins for manual review.
- Exports events and alerts to CSV files.
- Includes a safe, fictional sample log file.
- Uses only Python's standard library.

## Requirements
- Python 3.9 or newer
- No third-party packages required

## Run the project
Open a terminal in this extracted folder and run:

```bash
python app.py
```

Use a different log file:

```bash
python app.py path/to/auth.log
```

Change the alert threshold and output directory:

```bash
python app.py sample_logs/auth.log --threshold 5 --out reports
```

After execution, inspect `reports/events.csv` and `reports/alerts.csv`.

## GitHub upload
1. Extract the ZIP file.
2. Create a new GitHub repository, for example `cyber-log-threat-detector`.
3. Upload the contents of this folder (not the ZIP itself) to the repository, or use Git:

```bash
git init
git add .
git commit -m "Add Cyber Log Threat Detector"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/cyber-log-threat-detector.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username.

## How it works
1. Reads each line in the log file.
2. Uses regular expressions to identify authentication events.
3. Counts failures per source IP and account name.
4. Generates rule-based alerts when counts reach the configured threshold.
5. Writes normalized events and alerts to CSV reports.

## Limitations
- The parser currently targets common OpenSSH log message formats.
- Log formats vary by operating system and configuration; adjust patterns for your environment.
- A high count is a signal to investigate, not proof of malicious activity.
- The sample IP addresses and log entries are fictional documentation examples. Do not use this tool as a replacement for a monitored SIEM or incident-response process.

## Suggested future improvements
- Add timestamp parsing and time-window-based detection.
- Add a dashboard with charts.
- Support Windows event logs and additional Linux formats.
- Add unit tests and configurable detection rules.
- Add allowlists for known monitoring systems and administrators.

## Ethical use
Use this project only to analyze logs you own or are authorized to review. It is intended for defensive monitoring and learning.
