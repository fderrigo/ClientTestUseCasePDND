# ClientTestUseCasePDND

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![.NET 9](https://img.shields.io/badge/.NET-9.0-512BD4.svg)](https://dotnet.microsoft.com/download)

Client di test .NET 9 per l'interoperabilità **PDND** (Piattaforma Digitale Nazionale Dati).

Esegue il flusso OAuth2 *client credentials* con **client assertion JWT firmata** (RFC 7523, convenzioni PDND), ottiene un **voucher** (access token) dal token endpoint PDND e chiama un **e-service** esposto dietro gateway WSO2.

## Flusso

1. Carica la chiave privata RSA dal file PFX.
2. Genera una client assertion JWT firmata (`iss`/`sub` = clientId, claim custom `purposeId`).
3. POST della assertion al token endpoint → riceve `access_token` (voucher).
4. Chiama l'e-service con il voucher come `Bearer` token.

Un `LoggingHandler` logga tutto il traffico HTTP (token Authorization oscurato).

## Prerequisiti

- [.NET SDK 9](https://dotnet.microsoft.com/download)
- Un client e una finalità registrati sul portale PDND
- Il file PFX con la chiave privata RSA la cui chiave pubblica è caricata su PDND

## Setup

1. Copia il template di configurazione:

   ```bash
   cp appsettings.example.json appsettings.json
   ```

2. Compila `appsettings.json` con i valori presi dal portale PDND (vedi tabella sotto).
3. Metti il tuo PFX nella root del progetto (default `client-signing-key.pfx`).

> ⚠️ `appsettings.json` e i file `*.pfx` sono in `.gitignore`: **non vengono versionati**. Contengono segreti (password PFX, chiave privata). Non rimuoverli dal `.gitignore`.

### Configurazione (`appsettings.json`, sezione `Pdnd`)

| Campo | Descrizione |
|-------|-------------|
| `TokenUrl` | Token endpoint PDND (es. ambiente ATT/collaudo) |
| `ClientId` | ID del client registrato su PDND (usato come `iss`/`sub`) |
| `PurposeId` | ID della finalità associata al client |
| `Audience` | Audience attesa dal server per la client assertion |
| `KeyId` | `kid` della chiave pubblica caricata su PDND |
| `PfxPath` | Percorso del file PFX con la chiave privata |
| `PfxPassword` | Password del PFX |
| `EserviceUrl` | URL dell'e-service da chiamare |
| `HttpMethod` | Metodo HTTP per la chiamata (default `GET`) |

## Build & Run

```bash
dotnet build
dotnet run
```

L'app stampa: client assertion, voucher (in chiaro, per copia in Postman/curl), dump dei claim del JWT, dump HTTP completo della chiamata all'e-service e la risposta.

## Struttura

Tutto in `Program.cs`: caricamento config, generazione assertion, richiesta voucher, chiamata e-service, e gli helper di logging/decodifica JWT.

## Note

Tool di **debug/test**, non di produzione: il voucher viene stampato in chiaro e i segreti stanno in un file JSON locale. Per un uso reale, usare un secret manager. Commenti e output console sono in italiano.

## Sul blog

Scheda del progetto nella sezione Labs di [derrigo.it](https://www.derrigo.it): [PDND Test Client](https://www.derrigo.it/Products/Info/5/pdnd-test-client)

Articoli correlati:

- [L'ecosistema digitale nazionale](https://www.derrigo.it/Articles/Info/4/l-ecosistema-digitale-nazionale)
- [Paperopoli: un Comune finto costruito sul serio](https://www.derrigo.it/Articles/Info/8/paperopoli-un-comune-finto-costruito-sul-serio)

Chi sono: [Filippo D'Errigo](https://www.derrigo.it/Pages/Info/1/chi-sono)

## Licenza

Distribuito con licenza **Apache License 2.0**. Vedi i file [`LICENSE`](LICENSE) e [`NOTICE`](NOTICE).

Copyright © 2026 Filippo D'Errigo.

> "PDND", "PagoPA" e i marchi correlati appartengono ai rispettivi proprietari e sono citati solo per descrivere l'interoperabilità. Questo progetto non è affiliato né sponsorizzato da PagoPA S.p.A.
