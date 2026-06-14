# Production Checklist vol 9.1

## Enne deploy'd
- Vaheta kõik dev-secretid päris väärtuste vastu: `ADMIN_API_KEY`, `JWT_KEYRING_JSON`, `SECRET_ENCRYPTION_KEY`, `IP_HASH_PEPPER`, `WEBHOOK_SECRET_PEPPER`.
- Hoia saladused secret manageris või vähemalt orchestration layeri secret store'is, mitte commititud `.env` failis.
- Veendu, et `JWT_ACTIVE_KID` viitab tegelikult olemasolevale võtmele keyringis.
- Sea `ENVIRONMENT=prod`.
- Kontrolli, et Alembic migratsioonid jooksevad puhtalt: `alembic upgrade head`.

## Võrgustik ja piirid
- Ära ava Postgresi ja Redist internetti; kasuta private network'i.
- Pane API reverse proxy taha, kus on TLS lõpetus ja request size piirangud.
- Piira admin endpointidele ligipääs eraldi võrgureeglite või API gateway poliitikaga.

## Runtime hardening
- Jookse konteinerid non-root kasutajana.
- Kasuta `read_only` filesystemi ja `tmpfs` ajutiste failide jaoks.
- Lisa `no-new-privileges` ja eemalda Linux capability'd.
- Sea restart policy teenustele.

## Operatsiooniline valmisolek
- Kogu structured logs kesksele logiplatvormile.
- Kraabi `/metrics` Prometheusega.
- Sea alerting vähemalt järgmistele näitajatele:
  - 5xx kasv
  - replay_detected kasv
  - webhook dead-lettered sündmused
  - Redis/DB readiness vead
  - latency p95/p99 kasv

## Andmekaitse
- Auditlogides kasuta ainult `ip_hash` välja, mitte toor-IP-d.
- Defineeri retention policy `RequestLog`, `OutboxEvent` ja `WebhookDeliveryAttempt` tabelitele.
- Kirjelda selgelt, kui kaua webhook secret'e ja delivery attempt'e säilitatakse.

## Release kontroll
- Käivita enne deploy'd:
  - `pytest -q`
  - `python load/latency_probe.py --base-url http://127.0.0.1:8000 --path /healthz --requests 200 --concurrency 20`
- Kontrolli, et worker suudab töödelda outbox sündmuseid ja dead-letter rada on testitud.
- Kontrolli võtmerotatsiooni rollback-plaan: vana `kid` jääb decode keyringi seni, kuni vanad tokenid on aegunud.
