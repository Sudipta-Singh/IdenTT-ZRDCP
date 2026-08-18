# IdenTT local backend

A small local Express server that lets the IdenTT browser app send **real** email and SMS instead
of only simulated dispatch. It exists purely because browsers can't open SMTP sockets and can't
safely hold a Twilio Auth Token — this server holds those credentials instead, in a `.env` file
that never leaves your machine.

## Setup

```bash
cd server
npm install
cp .env.example .env
# edit .env with your own SMTP and/or Twilio credentials
npm start
```

By default it listens on `http://localhost:4737`. The browser app (`src/dispatch/realDispatch.js`)
talks to it there — no configuration needed on the app side unless you change `PORT`.

You do **not** need to fill in both email and Twilio — configure whichever you want to use. The
`/send-email` or `/send-sms` endpoint will return a clear "not configured" error for whichever one
is left blank, and the app's "Send for real" button will show that error instead of pretending it
worked.

## Endpoints

- `GET /health` → `{ ok, email, sms }` — whether each provider is configured.
- `POST /send-email` with `{ to, subject, text }`.
- `POST /send-sms` with `{ to, body }`.

## Security

This server has no authentication of its own and is meant to run only on `localhost`, for a single
local user, on the same machine as the browser app. Do not expose its port publicly or deploy it
as-is — anything that can reach it can send mail/SMS through your configured accounts.

## Without the backend

If you never run this server, IdenTT keeps working exactly as before — every challenge still uses
the existing simulated dispatch (`src/dispatch/simulate.js`), and the Requests tab's "Send for
real" button simply reports that it couldn't reach the backend.
