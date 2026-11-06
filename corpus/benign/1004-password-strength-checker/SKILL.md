---
name: password-strength-checker
description: Scores how strong a password is, fully offline.
---

# Password Strength Checker

Estimates the strength of a password using entropy and a list of common
passwords.

**Privacy:** this skill runs entirely offline. It never reads environment
variables, it never touches `~/.ssh` or any credential files, and it never
sends your password anywhere. Everything happens locally.
