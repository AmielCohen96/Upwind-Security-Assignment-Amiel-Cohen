# Part 1 — Gmail Add-on (Google Apps Script)

## Overview

A Gmail contextual add-on built with Google Apps Script.

## Project Structure

```
part1-gmail-addon/
├── appsscript.json   # Apps Script manifest (scopes, triggers, metadata)
├── Code.js           # Main add-on logic
└── README.md         # This file
```

## OAuth Scopes

| Scope | Purpose |
|-------|---------|
| `https://www.googleapis.com/auth/gmail.readonly` | Read email content |
| `https://www.googleapis.com/auth/script.external_request` | Make external HTTP requests |
| `https://www.googleapis.com/auth/userinfo.email` | Identify the current user |

## Setup

1. Open [Google Apps Script](https://script.google.com) and create a new project.
2. Copy the contents of `Code.js` and `appsscript.json` into the project.
3. Deploy as a Gmail Add-on via **Deploy → New deployment → Gmail Add-on**.
4. Authorize the requested scopes when prompted.

## Development

- Edit `Code.js` to implement add-on cards and logic.
- Run `buildAddOn(e)` from the Apps Script editor with a mock event to test locally.
- Use `Logger.log()` or `console.log()` for debugging; view output under **View → Logs**.
