# Release notes — vol 11

## Eesmärk
Puhastatud kliendile presenteeritav koondpakett koos dependency parandusega.

## Mis muudeti võrreldes vol 10-ga
- lisatud `cryptography==43.0.3` faili `requirements.txt`, sest `app/security.py` kasutab `cryptography.fernet` moodulit
- uuendatud paketi nimi vol 11 peale

## Mis säilitati vol 10-st
- eemaldatud varasemate etappide eraldi release notes failid
- eemaldatud tühjad kaustad ja runtime/test cache jäägid
- ühtlustatud juurkausta nimi `vol_11`
- lisatud koondatud executive summary, solution overview ja deployment guide
- säilitatud tehniline sisu, testid, migratsioonid, deploy failid ja load tööriistad
