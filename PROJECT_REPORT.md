# Project Report: Cyber Log Threat Detector

## Abstract
Authentication logs record login events that can help administrators identify suspicious access patterns. This project implements a lightweight Python log analyzer that identifies failed logins, invalid-user attempts, successful logins, and repeated failures from a source IP. It produces CSV reports for further inspection.

## Problem Statement
Reviewing authentication logs manually can be time-consuming. Repeated login failures may indicate a brute-force attempt, but they can be difficult to spot in a large text file. A simple rule-based tool can summarize relevant events and highlight activity that deserves review.

## Objectives
- Parse common SSH authentication messages.
- Summarize failed and successful login activity.
- Flag repeated failures using a configurable threshold.
- Export events and alerts in CSV format.
- Demonstrate basic defensive log analysis with Python.

## Tools and Technologies
- Python 3
- Regular expressions
- CSV file handling
- Command-line arguments
- Git and GitHub

## Methodology
1. Read the supplied authentication log.
2. Match log lines against patterns for failed logins, invalid users, and successful logins.
3. Count failed attempts by IP and username.
4. Create alerts for IP addresses exceeding the configured threshold.
5. Export events and alerts to CSV files.

## Testing Plan
- Run the program with the included sample log.
- Confirm that repeated failed attempts from `203.0.113.25` trigger an alert with the default threshold.
- Confirm that recognized events appear in `reports/events.csv`.
- Confirm that alerts appear in `reports/alerts.csv`.
- Run with a higher threshold and compare the resulting alerts.

## Results
Run `python app.py` to generate reports and observe the actual results in the terminal and CSV files. Results depend on the log input and threshold; no benchmark or real-world detection accuracy is claimed.

## Limitations
The program uses simple regular expressions and a fixed count threshold. It does not correlate events across a time window, enrich IP addresses with external intelligence, or prove malicious intent. The current parser targets common SSH log formats.

## Future Scope
Timestamp-aware detection, configurable rules, Windows event log support, automated unit tests, and a dashboard could improve usability and coverage.

## Conclusion
The project demonstrates a practical introduction to defensive security monitoring by turning text authentication logs into structured events and reviewable alerts.
