# Solution overview

## Põhivoog
1. Admin registreerib tenant'i, kliendi, seadme ja õiguse.
2. Klient väljastab kasutajale tokeni ainult siis, kui õigus kuulub samale omanikule.
3. `/request/access` kontrollib:
   - kliendi autentimist
   - tenant piire
   - tokeni kehtivust
   - owner-bindingut
   - replay kaitset
   - rate limitingut
   - riskiloogikat
4. Otsus logitakse auditina ning kirjutatakse välja outbox/webhook sündmustena.

## Turvamehhanismid
- admin endpointid on eraldi admin võtme taga
- owner mismatch annab 403
- replay tuvastus annab 409
- quota ületus annab kontrollitud vea
- DB write-path tõrge tagastab degradeeritud 503 vastuse

## Operatiivsus
- migratsioonid Alembicuga
- production compose ja entrypointid
- healthcheckid
- structured logging
- webhook retry/backoff ja delivery tracking
