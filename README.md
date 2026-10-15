# nandakrr.github.io

Personal site of **Nandakumar M**, Senior Application Security Engineer.

**Start here:** [nandakrr.github.io/hub](https://nandakrr.github.io/hub) is one page linking to everything below.

## Site map

| Area | Page | Link | Source |
|---|---|---|---|
| Career | Portfolio | [nandakrr.github.io](https://nandakrr.github.io/) | `index.html` |
| Career | Résumé (PDF) | [Download](https://nandakrr.github.io/Nandakumar_Senior_AppSec_Resume.pdf) | `Nandakumar_Senior_AppSec_Resume.pdf` |
| Career | Interview Preparation Lab | [nandakrr.github.io/int](https://nandakrr.github.io/int/) | `int/` |
| Security | Bug Bounty Target Picker | [nandakrr.github.io/bounty](https://nandakrr.github.io/bounty) | `bounty.html` |
| Fitness | Body Transformation Program | [nandakrr.github.io/1](https://nandakrr.github.io/1) | `1.html` |
| Fitness | Push / Pull / Legs (V-Taper) | [nandakrr.github.io/2](https://nandakrr.github.io/2) | `2.html` |
| Communication | English — Speak Coach | [nandakrr.github.io/lang/e](https://nandakrr.github.io/lang/e) | `lang/e.html` |
| Communication | German — Deutsch Coach | [nandakrr.github.io/lang/g](https://nandakrr.github.io/lang/g) | `lang/g.html` |
| Communication | Polish — Polski Coach | [nandakrr.github.io/lang/p](https://nandakrr.github.io/lang/p) | `lang/p.html` |
| Navigation | Workspace hub | [nandakrr.github.io/hub](https://nandakrr.github.io/hub) | `hub.html` |

## Interview Preparation Lab (`int/`)

Direct links to the most-used sections:

| Section | Link |
|---|---|
| Plan & progress | [/int/#home](https://nandakrr.github.io/int/#home) |
| Code review tests (practice + answer keys) | [/int/#reviews](https://nandakrr.github.io/int/#reviews) |
| Code review drills | [/int/#code](https://nandakrr.github.io/int/#code) |
| Headers & CSP lab | [/int/#headers](https://nandakrr.github.io/int/#headers) |
| Cloud IAM lab | [/int/#cloud](https://nandakrr.github.io/int/#cloud) |
| Threat model lab | [/int/#threat](https://nandakrr.github.io/int/#threat) |
| Architecture deep dives | [/int/#design](https://nandakrr.github.io/int/#design) |
| Question bank | [/int/#questions](https://nandakrr.github.io/int/#questions) |
| Mock interview | [/int/#mock](https://nandakrr.github.io/int/#mock) |

### Files

```
int/
├── index.html          # the app (all pages are hash routes: #home, #reviews, #headers, ...)
├── d-ref.js            # domain map + SaaS architecture data
├── d-labs.js           # code drills, threat models, triage, incidents, coding, behavioral
├── d-qbank.js          # question bank
├── d-v2.js … d-v7.js   # later modules (AI, metrics, cloud IAM, PDF questions, scenarios, headers/CSP)
└── code_review/        # code review tests shown on /int/#reviews
    ├── 01_document_service_ANSWERS.py
    ├── 02_WalletController_ANSWERS.java
    ├── 03_shop_api_ANSWERS.js
    ├── 04_internal_tools_ANSWERS.go
    ├── 05_ai_support_bot_ANSWERS.py
    ├── code_review_flask_marked.py
    ├── UserController_marked.java
    └── server_marked.js
```

### Adding a code review test

Answer files mark a finding at the end of the exact line:

```python
db.execute(f"... {sort}")   # LINE 87: [HIGH] SQL injection in ORDER BY ...
```

Use `#` for Python and `//` for Java/JS/Go. Severity is `[CRITICAL]`, `[HIGH]`, `[MEDIUM]` or `[LOW]`, and `NOT A VULN:` marks a safe decoy. A summary can follow the code after a separator line (`# ====...` or `// ====...`). Practice mode hides all of this automatically.

1. Upload the file to `int/code_review/`.
2. Add it to the `CR_FILES` list in `int/index.html` (the page only lists files named there).

## Notes

- Progress in the lab is stored in your browser (localStorage), so it doesn't sync between devices.
- Everything in this repo is public, including the lab's story bank.
