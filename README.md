# allGood?

TypeScript CLI for checking exact installed npm dependency versions from `package-lock.json` against the [OSV](https://osv.dev/) vulnerability database. This is a **reviewable starter**, not a complete security solution.

## Requirements

Node.js 20+, npm, and internet access to `api.osv.dev`.

## Develop

```sh
npm install
npm run build
npm test
npm run dev -- scan --path /path/to/project
```

## Commands

```sh
allgood scan --path /path/to/project
allgood scan --path /path/to/project --json
allgood scan --path /path/to/project --fail-on-findings
allgood watch --path /path/to/project
allgood watch --path /path/to/project --notify-webhook https://example.com/hook
allgood doctor --path /path/to/project
allgood help-schedule
```

`watch` runs **once** and stores previously seen findings in `~/.allgood/state.json`. Schedule it with cron or systemd timer. New findings print to stdout; optionally POST a JSON payload to a user-specified HTTPS webhook. Failed scans/webhook requests do not advance state. The first successful run reports all existing findings as new.

## Cron example

```cron
0 */6 * * * /usr/local/bin/allgood watch --path /srv/my-app >> /var/log/allgood.log 2>&1
```

Make sure the executable path is correct and cron has permission to read the project lockfile. Prefer an unprivileged service account. Do not include secret webhook tokens directly in shared cron configuration.


