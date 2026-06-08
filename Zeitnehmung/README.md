# ALPIN TIMING PRO – Server (Benutzerkonten, Internet)

Start (Tablet) und Ziel (Laptop) sind am Berg getrennt – deshalb läuft alles **über das Internet** mit einem **Server in der Cloud**. Statt einer PIN gibt es **Benutzerkonten**:

- **Ein Konto = ein Rennen** (ein „Raum").
- Wer mit dem Konto **angemeldet** ist (Ziel-Laptop, optional Start-Tablet), darf senden – **keine PIN**.
- **Zuschauer** öffnen den öffentlichen Link des Kontos – **ohne Anmeldung**, nur ansehen.

```
  [Ziel-Laptop  – angemeldet als „alice" = Master]  ─┐
  [Start-Tablet – angemeldet als „alice" = Station]  ─┤→ [SERVER, Raum „alice"] → [Zuschauer: …/?room=alice#results]
```

## ⚠️ Genauigkeit (wie gehabt)
Über getrennte Geräte synchronisiert die App die Uhren über den Server (NTP-artig): realistisch **einige Hundertstel bis Zehntel** – gut für Training/Verein/Zuschauer, **nicht** offizielle 1/100. Dafür bräuchte es GPS-synchronisierte Zeitmess-Boxen (deren Zeitstempel werden automatisch genutzt). Gemessen wird nie über die Internet-Ankunftszeit, sondern über synchronisierte Zeitstempel.

---

## Dateien (in denselben Ordner)
`alpin-timing.html`, `server.js`, `package.json`

## 1) Server starten
Lokal zum Üben:
```bash
npm install
npm start            # http://localhost:3000
```
In die Cloud (z.B. Render.com):
1. Ordner als GitHub-Repo hochladen.
2. „New Web Service" → Build `npm install`, Start `node server.js`.
3. **Wichtig:** Umgebungsvariable `AUTH_SECRET` auf einen langen Zufallswert setzen (sonst werden bei jedem Neustart alle Logins ungültig).
4. Adresse merken, z.B. `https://dein-rennen.onrender.com`.

> Hinweis Datenspeicher: Konten liegen in `data/users.json` auf dem Server. Auf Gratis-Tarifen mit „ephemerem" Speicher können sie bei einem Redeploy verloren gehen – für Dauerbetrieb einen Tarif mit persistentem Datenträger oder eine Datenbank verwenden.

## 2) Konto anlegen & senden (Ziel-Laptop)
1. `https://dein-rennen.onrender.com` öffnen.
2. Einstellungen ⚙ → **Vernetzung & Konto** → Benutzer + Passwort → **Registrieren** (beim ersten Mal), danach **Anmelden**.
3. **„Diesen PC als Master senden"** aktivieren.
4. Startliste eintragen, Ziel-Lichtschranke verbinden (oder Taste ⏎ als Ziel).

## 3) Start-Tablet (optional, falls es senden soll)
- `…/?room=DEINBENUTZER#start` öffnen → oben **„Als Startstation"** → mit **demselben Konto** anmelden → großer **START-Knopf**.
- Soll das Tablet nur zuschauen: einfach `…/?room=DEINBENUTZER#start` offen lassen, nichts antippen.

## 4) Zuschauer
- Öffentlicher Link: **`…/?room=DEINBENUTZER#results`** – in der App per **🔗 LiveTiming** → „Link kopieren" erzeugbar und teilbar.

## Adressen
| Zweck | Adresse |
|------|---------|
| Bedienung / Master (Ziel) | `…/` (angemeldet) |
| Start-Ansicht / -Station | `…/?room=BENUTZER#start` |
| Live-Ergebnisse (Zuschauer) | `…/?room=BENUTZER#results` |

## App aktualisieren (für dich als Entwickler)
Es gibt **eine** Quelle: die `alpin-timing.html` auf dem Server. So spielst du Änderungen ein:
1. HTML ändern (mit mir) und dabei die Versionsnummer erhöhen: in der Datei `const VERSION="1.0"` → z. B. `"1.1"`.
2. Neue Datei auf den Server legen (lokal ersetzen) bzw. in der Cloud neu deployen (bei Render: neuen Stand zu GitHub pushen, Render baut automatisch).
3. Fertig. Laufende Apps fragen regelmäßig `/api/version` ab und zeigen oben **„Neue Version verfügbar – Jetzt laden"**. Nach dem Neu-Laden hat jeder den aktuellen Stand.

Eine separate „Entwickler-App" brauchst du dafür nicht – der Server verteilt automatisch die jeweils hochgeladene Version.

## Sicherheit
- Passwörter werden mit **scrypt** gehasht gespeichert, Sitzungen über **signierte Tokens** (HMAC).
- Für echten Produktivbetrieb: **HTTPS erzwingen** (bei Render/Railway automatisch), starkes `AUTH_SECRET`, ggf. Rate-Limiting und eine richtige Datenbank. Diese Lösung ist eine solide, schlanke Basis – kein Ersatz für einen professionellen Identitätsdienst.
- Ohne Server läuft die Zeitnahme weiterhin **lokal auf einem PC** (ohne Konto/Internet).

Zeitnahme-Hilfe für Vereins-, Trainings- und Hobbyrennen – ohne Gewähr, nicht FIS-homologiert.
