# NULL200OK_fetch_DomXss

**Runtime DOM-based XSS, Trusted Types, DOMPurify & prototype pollution detector for modern browsers.**

A Manifest V3 extension that instruments the browser at three layers — page hooks, an isolated content script, and a central Service Worker taint engine — to detect client-side data-flow vulnerabilities as they happen. It also performs static CFG/PDG analysis on inline scripts and can instrument bundled DOMPurify via the Chrome DevTools Protocol.

[![Build](https://github.com/null200ok/NULL200OK_fetch_DomXss/actions/workflows/build.yml/badge.svg)](https://github.com/null200ok/NULL200OK_fetch_DomXss/actions)
![Version](https://img.shields.io/badge/version-4.0.0-blue)
![Manifest](https://img.shields.io/badge/manifest-v3-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Quick start

```bash
git clone https://github.com/null200ok/NULL200OK_fetch_DomXss.git
cd NULL200OK_fetch_DomXss
npm install