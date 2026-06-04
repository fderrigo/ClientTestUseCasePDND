using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Client di test per il flusso PDND (Piattaforma Digitale Nazionale Dati).
///
/// Cosa fa questo programma:
/// 1. Carica la chiave RSA privata dal file PFX (il certificato che ho registrato su PDND)
/// 2. Genera una "client assertion" JWT firmata con quella chiave — serve a dimostrare
///    al server di autenticazione PDND che siamo noi (il client registrato)
/// 3. Invia la client assertion al token endpoint PDND per ottenere un "voucher"
///    (access token OAuth2) tramite grant_type=client_credentials
/// 4. Usa il voucher come Bearer token per chiamare l'e-service esposto dietro il gateway WSO2
///
/// Il flusso segue la specifica RFC 7523 (JWT Bearer client authentication) adattata
/// alle convenzioni PDND (claim custom come purposeId).
///
/// Tutti i valori di configurazione (URL, ID, chiavi, password) vengono letti da
/// appsettings.json (NON versionato — vedi appsettings.example.json per il template).
/// Questo e' un client di debug/test, non un servizio di produzione.
/// </summary>
internal class Program
{
    /// <summary>
    /// Entry point — esegue l'intero flusso in sequenza:
    /// carica config -> carica certificato -> genera assertion -> richiede voucher -> chiama e-service.
    /// Se qualcosa va storto, stampa l'errore completo su stderr cosi' vedo subito lo stack trace.
    /// </summary>
    private static async Task Main()
    {
        try
        {
            // Carico la configurazione da appsettings.json (segreti fuori dal codice).
            var cfg = LoadConfig();

            // Carico il certificato PFX con la chiave privata.
            // EphemeralKeySet: non lo salvo nel key store di Windows, lo tengo solo in memoria.
            // Exportable: mi serve perche' poi devo estrarre la chiave RSA per firmare il JWT.
            var cert = X509CertificateLoader.LoadPkcs12FromFile(
                cfg.PfxPath,
                cfg.PfxPassword,
                X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

            // STEP 1: genero la client assertion JWT firmata con la mia chiave privata
            string clientAssertion = BuildClientAssertionJwt(cert, cfg.ClientId, cfg.PurposeId, cfg.Audience, cfg.KeyId);
            Console.WriteLine("✅ Client assertion generata.");

            // STEP 2: invio la client assertion al token endpoint e ottengo il voucher (access token)
            string voucher = await RequestVoucherAsyncCurlStyle(cfg.TokenUrl, cfg.ClientId, clientAssertion);
            Console.WriteLine("✅ Voucher ottenuto.");

            // Stampo il voucher in chiaro cosi' posso copiarlo e usarlo in Postman/curl per debug
            Console.WriteLine();
            Console.WriteLine("===== PDND VOUCHER (COPIA DA QUI) =====");
            Console.WriteLine(voucher);
            Console.WriteLine("===== FINE VOUCHER =====");
            Console.WriteLine();

            // Decodifico il voucher JWT e stampo i claim principali — utile per verificare
            // che il server PDND abbia emesso il token con i valori giusti
            // (client_id, purposeId, eserviceId, scadenze, ecc.)
            DumpJwt("VOUCHER", voucher);

            // STEP 3: chiamo l'e-service vero e proprio col voucher come Bearer token
            await CallEserviceAsync_Debug(voucher, cfg.EserviceUrl, cfg.HttpMethod);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("❌ ERRORE:");
            Console.Error.WriteLine(ex);
        }
    }

    /// <summary>
    /// Carica la configurazione PDND da appsettings.json (sezione "Pdnd").
    /// I segreti (password PFX, ID client) stanno qui e NON nel codice versionato.
    /// Se manca appsettings.json o un campo obbligatorio, lancia un errore esplicito
    /// che rimanda al template appsettings.example.json.
    /// </summary>
    private static PdndConfig LoadConfig()
    {
        var root = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            .Build();

        var cfg = root.GetSection("Pdnd").Get<PdndConfig>()
            ?? throw new InvalidOperationException(
                "Sezione 'Pdnd' mancante in appsettings.json. Copia appsettings.example.json in appsettings.json e compilala.");

        cfg.Validate();
        return cfg;
    }

    /// <summary>
    /// Costruisce la client assertion JWT secondo le specifiche PDND.
    ///
    /// La client assertion e' un JWT firmato che il client invia al token endpoint
    /// per autenticarsi (al posto di un client_secret). Il server PDND verifica la firma
    /// usando la chiave pubblica che ho caricato in fase di registrazione del client.
    ///
    /// Struttura del JWT:
    /// - Header: alg=RS256, typ=JWT, kid=<id della chiave pubblica su PDND>
    /// - Payload:
    ///   - iss/sub = clientId (chi sono)
    ///   - aud = URL dell'authorization server (a chi e' destinato il token)
    ///   - jti = UUID random (previene replay attack — ogni assertion e' unica)
    ///   - iat = timestamp di emissione
    ///   - exp = scadenza (iat + 5 minuti — PDND non accetta assertion troppo longeve)
    ///   - purposeId = finalita' PDND (claim custom, non standard OAuth2)
    /// </summary>
    private static string BuildClientAssertionJwt(
        X509Certificate2 signingCert,
        string clientId,
        string purposeId,
        string audience,
        string kid)
    {
        // Estraggo la chiave privata RSA dal certificato — mi serve per firmare
        using RSA? rsa = signingCert.GetRSAPrivateKey();
        if (rsa == null) throw new InvalidOperationException("Nel PFX non trovo una RSA private key.");

        // Calcolo iat (issued at) e exp (expiration) come Unix timestamp in secondi.
        // 5 minuti di validita' e' il massimo che PDND accetta per una client assertion.
        var now = DateTimeOffset.UtcNow;
        var iat = now.ToUnixTimeSeconds();
        var exp = now.AddMinutes(5).ToUnixTimeSeconds();

        // Creo le signing credentials con RSA-SHA256 (l'unico algoritmo supportato da PDND)
        var securityKey = new RsaSecurityKey(rsa) { KeyId = kid };
        var creds = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        // Costruisco l'header — forzo typ=JWT e kid perche' la libreria non sempre
        // li imposta come vuole PDND
        var header = new JwtHeader(creds);
        header["typ"] = "JWT";
        header["kid"] = kid;

        // Costruisco il payload con i claim richiesti da PDND
        var payload = new JwtPayload
        {
            { "iss", clientId },        // issuer: il mio client
            { "sub", clientId },        // subject: uguale a iss per client_credentials
            { "aud", audience },        // audience: il token endpoint PDND
            { "jti", Guid.NewGuid().ToString() }, // JWT ID univoco (anti-replay)
            { "iat", iat },             // issued at: quando l'ho generato
            { "exp", exp },             // expires: quando scade (iat + 5min)
            { "purposeId", purposeId }  // claim custom PDND: la finalita' di accesso
        };

        // Assemblo e serializzo il JWT (header.payload.signature in base64url)
        var token = new JwtSecurityToken(header, payload);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Invia la client assertion al token endpoint PDND e ottiene il voucher (access token).
    ///
    /// Fa una POST application/x-www-form-urlencoded con questi parametri:
    /// - client_id: il mio ID client
    /// - client_assertion: il JWT firmato che ho appena generato
    /// - client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" (standard RFC 7523)
    /// - grant_type: "client_credentials" (non c'e' un utente, e' machine-to-machine)
    ///
    /// Se tutto va bene, il server risponde con un JSON che contiene "access_token" —
    /// quello e' il voucher PDND che poi uso come Bearer per chiamare l'e-service.
    ///
    /// Il nome "CurlStyle" e' perche' ho modellato la request come farei con curl,
    /// impostando ogni header e parametro esplicitamente per avere il massimo controllo
    /// durante il debug.
    /// </summary>
    private static async Task<string> RequestVoucherAsyncCurlStyle(string tokenUrl, string clientId, string clientAssertion)
    {
        // Uso il LoggingHandler per vedere esattamente cosa mando e cosa ricevo —
        // fondamentale quando devo capire perche' il token endpoint mi rifiuta
        using var http = new HttpClient(new LoggingHandler(new HttpClientHandler()))
        {
            Timeout = TimeSpan.FromSeconds(60)
        };

        // Parametri del form POST secondo la specifica OAuth2 + RFC 7523
        var form = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["client_assertion"] = clientAssertion,
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["grant_type"] = "client_credentials"
        };

        // FormUrlEncodedContent codifica automaticamente i valori (url-encode)
        using var content = new FormUrlEncodedContent(form);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

        using var req = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
        {
            Content = content
        };

        // Header custom di tracciamento — lo cerco nei log del server quando devo debuggare
        // un problema lato PDND/gateway
        req.Headers.TryAddWithoutValidation("X-Debug-Trace", "pdnd-token-01");

        // Invio la richiesta e leggo la risposta
        using var resp = await http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();

        // Se il server risponde con errore, lancio eccezione con status code e body
        // cosi' vedo subito cosa non va (es. "invalid_client", "invalid_grant", ecc.)
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Token request fallita: {(int)resp.StatusCode} {resp.ReasonPhrase}\n{body}");

        // Parso il JSON di risposta e cerco il campo "access_token"
        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("access_token", out var accessTokenEl))
            throw new InvalidOperationException("Risposta OK ma access_token non trovato. Body: " + body);

        var accessToken = accessTokenEl.GetString();
        if (string.IsNullOrWhiteSpace(accessToken))
            throw new InvalidOperationException("access_token vuoto. Body: " + body);

        return accessToken!;
    }

    /// <summary>
    /// Chiama l'e-service target usando il voucher PDND come Bearer token.
    ///
    /// Questa e' la chiamata "vera" all'API che sta dietro il gateway WSO2.
    /// Ho aggiunto un sacco di logging per il debug perche' quando qualcosa non funziona
    /// devo capire se il problema e':
    /// - nel voucher (token scaduto, claim sbagliati)
    /// - nel gateway WSO2 (configurazione subscription, policy)
    /// - nell'API backend (errore applicativo)
    ///
    /// Stampo: URL, trace ID, header di Authorization, status code, tutti gli header
    /// di risposta e il body completo.
    /// </summary>
    private static async Task CallEserviceAsync_Debug(string voucher, string eserviceUrl, string httpMethod)
    {
        // Anche qui uso il LoggingHandler per avere il dump HTTP completo
        var handler = new LoggingHandler(new HttpClientHandler());

        using var http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(60)
        };

        // Trace ID che poi cerco nei log di WSO2 per correlare la richiesta
        var trace = "pdnd-01";
        var method = new HttpMethod(httpMethod.ToUpperInvariant());
        using var req = new HttpRequestMessage(method, eserviceUrl);

        // Il voucher PDND va nell'header Authorization come Bearer token —
        // il gateway WSO2 lo valida e lo inoltra al backend
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", voucher);

        // Header di tracciamento per il gateway
        req.Headers.TryAddWithoutValidation("X-Debug-Trace", trace);

        // User-Agent e Accept li metto esplicitamente perche' alcuni gateway/proxy
        // si comportano male se mancano (WSO2 in passato mi ha dato problemi senza)
        req.Headers.UserAgent.ParseAdd("pdnd-wso2-debug/1.0");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        // Correlation ID univoco per tracciare la richiesta end-to-end
        req.Headers.TryAddWithoutValidation("x-correlation-id", Guid.NewGuid().ToString());

        // Stampo un riepilogo prima di inviare, cosi' vedo cosa sto per mandare
        Console.WriteLine("\n=== CALL E-SERVICE ===");
        Console.WriteLine($"URL: {eserviceUrl}");
        Console.WriteLine($"Trace: {trace}");
        Console.WriteLine($"Authorization header set? {(req.Headers.Authorization != null ? "YES" : "NO")}");
        if (req.Headers.Authorization != null)
            Console.WriteLine($"Authorization scheme: {req.Headers.Authorization.Scheme} (token length: {req.Headers.Authorization.Parameter?.Length ?? 0})");

        // Invio la richiesta all'e-service
        using var resp = await http.SendAsync(req);
        var body = await resp.Content.ReadAsStringAsync();

        // Stampo tutto cio' che torna: status, header, body — utile per capire
        // se il gateway ha accettato il token e cosa ha risposto il backend
        Console.WriteLine($"\n➡️ e-service status: {(int)resp.StatusCode} {resp.ReasonPhrase}");
        Console.WriteLine("---- response headers ----");
        foreach (var h in resp.Headers)
            Console.WriteLine($"{h.Key}: {string.Join(", ", h.Value)}");
        foreach (var h in resp.Content.Headers)
            Console.WriteLine($"{h.Key}: {string.Join(", ", h.Value)}");

        Console.WriteLine("---- response body ----");
        Console.WriteLine(body);
    }

    /// <summary>
    /// Decodifica un JWT (senza verificare la firma) e stampa header e claim principali.
    ///
    /// Lo uso per ispezionare il voucher che mi ritorna PDND e verificare che contenga
    /// i claim giusti: client_id, purposeId, eserviceId, descriptorId, e le scadenze.
    /// Se qualcuno di questi manca o e' sbagliato, so che il problema e' nella configurazione
    /// su PDND (client, finalita', e-service) e non nel mio codice.
    /// </summary>
    private static void DumpJwt(string label, string jwt)
    {
        Console.WriteLine($"\n=== {label} JWT DUMP ===");
        try
        {
            var handler = new JwtSecurityTokenHandler();
            // ReadJwtToken decodifica senza validare la firma — perfetto per debug
            var token = handler.ReadJwtToken(jwt);

            // Stampo tutti i campi dell'header (alg, typ, kid)
            Console.WriteLine("Header:");
            foreach (var kv in token.Header)
                Console.WriteLine($"  {kv.Key}: {kv.Value}");

            // Estraggo i claim standard OAuth2/JWT
            string iss = token.Issuer;
            string aud = token.Audiences?.FirstOrDefault() ?? "(none)";
            long exp = GetLongClaim(token, "exp");
            long nbf = GetLongClaim(token, "nbf");
            long iat = GetLongClaim(token, "iat");

            // Stampo i claim standard con timestamp convertiti in formato leggibile
            Console.WriteLine("Payload key claims:");
            Console.WriteLine($"  iss: {iss}");
            Console.WriteLine($"  aud: {aud}");
            Console.WriteLine($"  iat: {iat} ({UnixToUtc(iat)})");
            Console.WriteLine($"  nbf: {nbf} ({UnixToUtc(nbf)})");
            Console.WriteLine($"  exp: {exp} ({UnixToUtc(exp)})");

            // Stampo i claim specifici PDND — questi me li aspetto nel voucher
            // se la finalita' e l'e-service sono configurati correttamente
            Console.WriteLine("PDND claims:");
            Console.WriteLine($"  client_id: {GetStringClaim(token, "client_id")}");
            Console.WriteLine($"  purposeId: {GetStringClaim(token, "purposeId")}");
            Console.WriteLine($"  eserviceId: {GetStringClaim(token, "eserviceId")}");
            Console.WriteLine($"  descriptorId: {GetStringClaim(token, "descriptorId")}");
        }
        catch (Exception ex)
        {
            Console.WriteLine("⚠️ Impossibile decodificare JWT: " + ex.Message);
        }
        Console.WriteLine("========================\n");
    }

    /// <summary>
    /// Cerca un claim per nome nel JWT e ne ritorna il valore stringa.
    /// Ritorna "(missing)" se il claim non esiste — cosi' nel dump vedo subito cosa manca.
    /// </summary>
    private static string GetStringClaim(JwtSecurityToken token, string name)
        => token.Claims.FirstOrDefault(c => c.Type == name)?.Value ?? "(missing)";

    /// <summary>
    /// Come GetStringClaim, ma parsa il valore come long (per i timestamp Unix).
    /// Ritorna 0 se il claim non esiste o non e' numerico.
    /// </summary>
    private static long GetLongClaim(JwtSecurityToken token, string name)
    {
        var v = token.Claims.FirstOrDefault(c => c.Type == name)?.Value;
        return long.TryParse(v, out var n) ? n : 0;
    }

    /// <summary>
    /// Converte un timestamp Unix (secondi) in stringa ISO 8601 UTC.
    /// Lo uso nel dump JWT per rendere leggibili iat/nbf/exp.
    /// Ritorna "(n/a)" se il timestamp e' 0 o negativo (claim assente).
    /// </summary>
    private static string UnixToUtc(long unix)
    {
        if (unix <= 0) return "(n/a)";
        return DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime.ToString("O");
    }

    /// <summary>
    /// Configurazione PDND, mappata dalla sezione "Pdnd" di appsettings.json.
    /// Tutti i valori si prendono dal portale PDND dopo aver registrato client e finalita'.
    /// </summary>
    private sealed class PdndConfig
    {
        /// URL del token endpoint PDND (es. ambiente ATT = collaudo interoperabilita')
        public string TokenUrl { get; set; } = "";

        /// ID del client registrato su PDND — usato come "iss" e "sub" nella client assertion
        public string ClientId { get; set; } = "";

        /// ID della finalita' (purpose) associata al client — PDND lo richiede nel JWT
        public string PurposeId { get; set; } = "";

        /// Audience della client assertion — deve combaciare con quello atteso dal server PDND
        public string Audience { get; set; } = "";

        /// Key ID (kid) della chiave pubblica caricata su PDND — il server lo usa per
        /// trovare la chiave con cui verificare la firma del JWT
        public string KeyId { get; set; } = "";

        /// Percorso del file PFX con la chiave privata RSA (NON versionato)
        public string PfxPath { get; set; } = "";

        /// Password del PFX
        public string PfxPassword { get; set; } = "";

        /// URL dell'e-service da chiamare, esposto dietro il gateway WSO2
        public string EserviceUrl { get; set; } = "";

        /// Metodo HTTP per la chiamata all'e-service (default GET)
        public string HttpMethod { get; set; } = "GET";

        /// <summary>
        /// Verifica che i campi obbligatori siano valorizzati; altrimenti errore esplicito.
        /// </summary>
        public void Validate()
        {
            var missing = new List<string>();
            if (string.IsNullOrWhiteSpace(TokenUrl)) missing.Add(nameof(TokenUrl));
            if (string.IsNullOrWhiteSpace(ClientId)) missing.Add(nameof(ClientId));
            if (string.IsNullOrWhiteSpace(PurposeId)) missing.Add(nameof(PurposeId));
            if (string.IsNullOrWhiteSpace(Audience)) missing.Add(nameof(Audience));
            if (string.IsNullOrWhiteSpace(KeyId)) missing.Add(nameof(KeyId));
            if (string.IsNullOrWhiteSpace(PfxPath)) missing.Add(nameof(PfxPath));
            if (string.IsNullOrWhiteSpace(EserviceUrl)) missing.Add(nameof(EserviceUrl));
            if (missing.Count > 0)
                throw new InvalidOperationException(
                    "Campi mancanti nella sezione 'Pdnd' di appsettings.json: " + string.Join(", ", missing));
        }
    }

    /// <summary>
    /// DelegatingHandler custom che logga su console le request HTTP in uscita
    /// e le response in arrivo. Lo uso come wrapper attorno a HttpClientHandler
    /// per avere visibilita' completa sul traffico HTTP durante il debug.
    ///
    /// Attenzione: l'header Authorization viene stampato con il token oscurato
    /// (mostra solo lo schema e la lunghezza) per evitare di esporre il voucher
    /// nei log — anche se questo e' un tool di debug, meglio non rischiare
    /// di copiare/incollare token validi in posti sbagliati.
    /// </summary>
    private sealed class LoggingHandler : DelegatingHandler
    {
        public LoggingHandler(HttpMessageHandler inner) : base(inner) { }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Loggo la request: metodo, URL e tutti gli header
            Console.WriteLine("\n--- HTTP REQUEST ---");
            Console.WriteLine($"{request.Method} {request.RequestUri}");
            foreach (var h in request.Headers)
            {
                // L'Authorization lo oscuro — stampo solo schema e lunghezza del token
                if (string.Equals(h.Key, "Authorization", StringComparison.OrdinalIgnoreCase))
                {
                    var val = request.Headers.Authorization;
                    Console.WriteLine($"Authorization: {val?.Scheme} <redacted> (len={val?.Parameter?.Length ?? 0})");
                }
                else
                {
                    Console.WriteLine($"{h.Key}: {string.Join(", ", h.Value)}");
                }
            }

            // Se c'e' un body (es. il form POST per il token), loggo anche i content header
            if (request.Content != null)
            {
                foreach (var h in request.Content.Headers)
                    Console.WriteLine($"{h.Key}: {string.Join(", ", h.Value)}");
            }

            // Eseguo la richiesta vera e propria
            var resp = await base.SendAsync(request, cancellationToken);

            // Loggo la response: solo status code e reason phrase
            // (gli header e il body li stampa il chiamante, non qui)
            Console.WriteLine("--- HTTP RESPONSE ---");
            Console.WriteLine($"HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}");
            return resp;
        }
    }
}
