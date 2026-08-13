# Password Strength Analyzer & Generator

Scores password strength via entropy calculation, flags weak patterns
(keyboard walks, sequences, repeats, dates, common passwords), and
generates cryptographically secure passwords/passphrases.

## Usage
```bash
python password_analyzer.py --check "MyP@ssw0rd"
python password_analyzer.py --generate 16
python password_analyzer.py --passphrase 5
python password_analyzer.py --interactive
```
