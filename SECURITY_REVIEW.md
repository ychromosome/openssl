Security Review: Provider-definierte TLS-1.3-Ciphersuites
=========================================================

Zweiter Durchgang (Stand `reviewtest` = 0bd50c5, Testlücken aktualisiert auf f0e6022)
------------------------------------------------

Die Serie wurde nach dem ersten Durchgang umgeschrieben (gleiche acht Commits,
neue Hashes). Der `crypto/`-Anteil ist byteidentisch zum ersten Stand; die
Änderungen gegenüber dem ersten Review betreffen `ssl/ssl_lib.c`,
`ssl/ssl_ciph.c`, `ssl/statem/extensions_srvr.c`, Dokumentation, CHANGES und
Tests.

### Status der Befunde aus dem ersten Durchgang

| Nr. | Status | Nachweis |
|-----|--------|----------|
| F1 Quadratische ClientHello-Verarbeitung | **behoben** | Deduplizierung in `ossl_bytes_to_cipher_list` entfernt (`ssl/ssl_lib.c:7685-7700`). Messung Release-Build, 32 766 Einträge: nur statisch 1,2 ms, halb statisch/halb Provider 2,4 ms (vorher 1107 ms), nur Provider 2,9 ms. `ssl3_choose_cipher` über dieselbe Liste mit und ohne Server-Präferenz: unter 0,1 ms. Neuer Test `test_provider_peer_list_maximum` deckt den früheren Worst Case ab. |
| F2 Session überlebt OSSL_LIB_CTX | **dokumentiert, nicht behoben** | Code unverändert; `doc/designs/provider-tls-ciphersuites.md:16-21`, `SSL_SESSION_get0_cipher.pod`, `SSL_get_ciphers.pod`, `provider-base(7)` und der Test-Helper benennen die Reihenfolge jetzt als Pflicht. Der Use-after-free bei Verletzung bleibt bestehen (siehe Restrisiko unten); ein Test für die Reihenfolge fehlt weiterhin (T1). |
| F3 Fehlerhafter Provider legt SSL_CTX_new lahm | **dokumentiert** | CHANGES.md nennt das Verhalten jetzt ausdrücklich; Code unverändert, bewusste Entscheidung. |
| F4 SSL_CIPHER_description() liefert NULL | **behoben** | `ssl/ssl_ciph.c:2154-2159` kürzt bei übergebenem Puffer wieder; NULL nur für allozierte Puffer, `len < 128` oder Formatfehler. Doku angepasst, Test `test_provider_max_name_description` (128-Byte-Puffer mit 255-Zeichen-Namen). |
| F5 Alert bei unzulässiger externer PSK-Session | **behoben** | `extensions_srvr.c:1394-1397` sendet `internal_error`; Test prüft den Alert. |
| F6 `prov->libctx` auf konkreten Kontext gepinnt | **dokumentiert** | `doc/internal/man3/ossl_provider_new.pod`, CHANGES.md. |
| F7 Teardown der Child-Owner-Provider | **unverändert, kein Befund** | crypto-Diff identisch; erneut unter ASAN, Valgrind und TSAN ohne Auffälligkeit. |

### Eingesetzte Werkzeuge und Ergebnisse

- **ASAN-Build** (`enable-asan --debug`), vollständige Suiten: `test_provider_tls_ciphersuite`,
  `_ext`, `_nonresumption`, `_matrix`, `test_provider_tls_apps`,
  `test_provider_child_decoder`, `test_provfetch`, `test_tls13secrets`,
  `test_app_ciphers`, `test_evp_extra`, `test_sslapi`, `test_ssl_new`:
  12 Rezepte, 58 Tests, alle bestanden, keine ASAN- oder Leak-Meldung.
- **Valgrind memcheck** (Release-Build) auf `provider_tls_ciphersuite_test`,
  `provider_tls_ciphersuite_ext_test`, `provider_tls_nonresumption_test`,
  `provfetchtest`: 0 Fehler in 0 Kontexten.
- **ThreadSanitizer-Build** (`-fsanitize=thread no-asm`): `provider_tls_ciphersuite_test`,
  `provider_tls_nonresumption_test`, `provfetchtest` ohne Meldung.
  `provider_tls_ciphersuite_ext_test` meldet 17 Data Races, alle in
  `crypto/initthread.c:433/463/465/476` (`ossl_init_thread_start` gegen
  `init_thread_deregister`), ausgelöst durch `test_concurrent_provider_discovery_reload`.
  Der Code ist von der Serie unberührt; Einordnung unter "Nicht gemeldet".
- **gcc -fanalyzer** über alle geänderten Dateien: 7 NULL-Dereferenz-Warnungen,
  alle in unberührten Upstream-Zeilen (`ssl_lib.c:1067,1900,1928,5512,5926,5941`,
  `t1_lib.c:5344`). **clang --analyze** (core, unix, security, alpha.unix,
  alpha.security): nur `insecureAPI`-Rauschen, zwei tote Zuweisungen
  (`t1_lib.c:382` Initialwert von `reason`, `t1_lib.c:2857/2865` Upstream) und ein
  Upstream-Fund in `statem_srvr.c:3027`. Nichts in den neuen Pfaden.
- **Eigene Probes** (ASAN, statisch gegen libssl/libcrypto gelinkt, nicht im Baum):
  - NewSessionTicket-Fuzzing: 20 000 zufällige und teilstrukturierte Bodies gegen
    Sessions mit Provider- und eingebautem Cipher, TLS 1.3 und 1.2: keine
    Speicherfehler, `max_early_data` und Provider-Marker bleiben bei
    Provider-Sessions unverändert.
  - Capability-Fuzzing: eigener Provider liefert 6000 zufällige
    `TLS-CIPHERSUITE`-Parametersätze (falsche Typen, NULL-Daten, `SIZE_MAX`,
    fehlende und doppelte Schlüssel, Abbruch mitten im Callback); 57 Kontexte
    entstanden, 5943 abgelehnt, keine Speicherfehler, alle angenommenen
    Deskriptoren liefern Beschreibung, Digest und ≥128 Bit.
  - `d2i_SSL_SESSION_ex` in-place in eine Provider-Session mit 20 000 mutierten
    DER-Eingaben: 13 494 dekodiert, 6506 abgelehnt; Cipher-Referenz nach
    Fehlschlag immer der Provider-Deskriptor oder ein statischer, Marker nach
    Erfolg gelöscht, kein Refcount-Fehler.
  - 3000 zufällige `cipher_suites`-Listen bis 70 KB durch
    `SSL_bytes_to_cipher_list()` und `SSL_get_shared_ciphers()` mit zufälligen
    Puffergrößen: sauber.
  - Zustandsloser HRR mit Cookie und Provider-Suite: Handshake erfolgreich.
  - Post-Handshake-Auth auf einer Provider-Session: Zertifikat angenommen,
    `sent_tickets` bleibt 0 (schließt Testlücke T4 empirisch).
  - 0-RTT: eingebautes Ticket mit `max_early_data`, Server bevorzugt die
    Provider-Suite gleicher Hashfunktion: Early Data wird abgelehnt
    (`SSL_READ_EARLY_DATA_FINISH`, beide Seiten `REJECTED`), Resumption in die
    Provider-Suite gelingt, Ergebnis-Session nicht resumierbar, Original-Session
    unverändert resumierbar (schließt T3 empirisch).
  - SNI-Wechsel in ein SSL_CTX aus einem anderen OSSL_LIB_CTX: siehe N1.

### Neue Hinweise aus dem zweiten Durchgang

**N1 – Niedrig, bestätigt: SNI-Wechsel in einen fremden OSSL_LIB_CTX wird nicht abgewiesen.**
Ort: `ssl/statem/extensions.c:1465-1479` (`final_server_name`),
`doc/designs/provider-tls-ciphersuites.md` ("Rebinding to another library
context ... is outside this design"). Probe: Server-SSL_CTX aus libctx A mit
Provider-Suite, Servername-Callback ruft `SSL_set_SSL_CTX()` mit einem SSL_CTX
aus libctx B. Der Handshake gelingt mit der Provider-Suite, sowohl wenn B die
Suite ebenfalls listet als auch wenn B nur eingebaute Suiten erlaubt. Die
Verbindung nutzt danach AEAD und Digest aus libctx A, während Zertifikat und
Konfiguration aus B stammen. Für eingebaute Suiten ist das Verhalten gleich
(die vor SNI gewählte Suite bleibt, Probe mit AES-128 gegen ein B, das nur
AES-256 erlaubt), sodass es keine neue Policy-Lücke ist; neu ist, dass die
Algorithmusimplementierung nicht mehr aus dem Kontext des aktiven SSL_CTX
kommt. Für einen auf einen eingeschränkten Kontext (z. B. FIPS-libctx)
umgeschalteten Vhost ist das überraschend. Vorschlag: in `final_server_name`
für Provider-Suiten `SSL_CONNECTION_GET_CTX(s)->libctx != s->session_ctx->libctx`
mit `NO_SHARED_CIPHER` abweisen, oder das Design-Dokument auf "wird toleriert,
Implementierung bleibt die des ursprünglichen Kontexts" ändern und T5 als
Test aufnehmen.

**N2 – Info: Provider-Namen in `system_default`-Konfiguration.** `Ciphersuites`
mit nur Provider-Namen schlägt für DTLS- oder TLSv1_2-Method-Kontexte in
`SSL_CTX_set_ciphersuites()` fehl; `ssl_do_config()` verwirft den Fehler für die
Systemkonfiguration (`ssl/ssl_mcnf.c:122-129`), `SSL_CTX_new()` gelingt mit der
Voreinstellung. Mit `config_diagnostics = 1` scheitert `SSL_CTX_new()`. Kein
Befund, aber für die Doku von `Ciphersuites` in `config(5)` erwähnenswert.

**N3 – Info: Design-Aussage zu Capability-Rückgabewerten.** Ein Provider, dessen
`get_capabilities` für unbekannte Capabilities 0 liefert, lässt bereits
`ssl_load_groups()` und damit `SSL_CTX_new()` scheitern (Upstream-Verhalten für
`TLS-GROUP`). Die neue Discovery behandelt 0 korrekt als "nicht unterstützt".
Die Formulierung in `provider-base(7)` könnte Provider-Autoren darauf hinweisen,
dass nur `TLS-CIPHERSUITE` diese Toleranz hat.

### Restrisiko F2

Die Dokumentation macht die Freigabe-Reihenfolge zur Pflicht, der Fehlerfall
ist aber weiterhin ein Heap-Use-after-free statt eines definierten Fehlers.
Das Risiko liegt bei Anwendungen, die Sessions aus `SSL_get1_session()` in
eigenen Strukturen halten und ihren OSSL_LIB_CTX vor diesen Strukturen
freigeben; vor dieser Serie war das unkritisch. Empfehlung bleibt: Test T1
aufnehmen und mittelfristig die EVP-Objekte nicht in der Session halten.

### Testlücken nach dem zweiten Durchgang

Eine Testlücke bezeichnet hier Verhalten, das die Serie bewusst festlegt
(per Code, Dokumentation oder Design-Dokument), für das es im Baum aber keinen
Test gibt. Das Verhalten kann korrekt sein; ohne Test schützt jedoch nichts
davor, dass eine spätere Änderung es unbemerkt kippt. Bei T1 wäre die Folge ein
Speicherfehler, bei T3 bis T5 eine Abweichung von der dokumentierten Policy.
Die unten genannten Probes liegen außerhalb des Repositories und können als
Vorlage für Tests in `test/provider_tls_ciphersuite_ext_test.c` dienen; sie
wurden auf Wunsch ("Code nicht ändern") nicht eingearbeitet.

- T1 (F2): weiterhin kein Test, der Session oder Deskriptor den OSSL_LIB_CTX
  überleben lässt. Die neue Doku-Pflicht ist nicht abgesichert.
- T2 (F1): geschlossen durch `test_provider_peer_list_maximum`.
- T3 (0-RTT in Provider-Suite): geschlossen auf f0e6022 durch
  `test_early_data_rejected_on_provider_transition`; unter ASAN ausgeführt,
  bestanden.
- T4 (PHA auf Provider-Session): geschlossen auf f0e6022 durch
  `test_provider_post_handshake_auth`; unter ASAN ausgeführt, bestanden.
- T5 (SNI in fremden libctx): bleibt offen. Laut Autor ist der
  Cross-LIB_CTX-Wechsel über `SSL_set_SSL_CTX()` auf Vorgabe des Maintainers
  in der Initialimplementierung bewusst nicht behandelt (siehe N1).
- Zu T1 hat der Autor entschieden, dass ein Session-Zugriff nach
  `OSSL_LIB_CTX_free()` außerhalb des dokumentierten Lebensdauervertrags liegt
  und deshalb nicht getestet wird. Die Empfehlung im Abschnitt "Restrisiko F2"
  bleibt als Hinweis stehen.

### Nicht gemeldet (Upstream-Kontext, zweiter Durchgang)

`test_concurrent_provider_discovery_reload` löst unter ThreadSanitizer den
bekannten Konflikt zwischen `ossl_init_thread_start()` (schreibt die
thread-lokale Handler-Liste ohne globale Sperre, `crypto/initthread.c:432-433`)
und `init_thread_deregister()` (liest alle Listen unter `gtr->lock`,
`crypto/initthread.c:453-477`) aus, hier über `ossl_provider_free()` →
`ossl_init_thread_deregister()` beim Freigeben eines Kontexts in einem Thread,
während ein anderer Thread per `RAND_bytes_ex()` im Provider-Init einen
Handler registriert. Der Code ist unverändert und das Muster unabhängig von
dieser Serie; ein TSAN-Lauf der neuen Testsuite wird dadurch jedoch rot.

---

Erster Durchgang (Stand 8a6d155)
--------------------------------

Geprüfter Bereich: `git diff 41eecc7c..reviewtest` (8 Commits, u. a.
`ssl/t1_lib.c`, `ssl/ssl_ciph.c`, `ssl/ssl_sess.c`, `ssl/ssl_asn1.c`,
`ssl/statem/*`, `ssl/tls13_enc.c`, `crypto/provider_core.c`,
`crypto/property/property.c`, `crypto/context.c`). Upstream-Code wurde nur
als Kontext gelesen; dort gefundene, vorbestehende Probleme sind nicht als
Befund aufgeführt (siehe Abschnitt "Nicht gemeldet").

Methode: statische Durchsicht des Diffs gegen `doc/designs/provider-tls-ciphersuites.md`,
plus ASAN-Build (`enable-asan --debug`) und ein optimierter Build
(`--release`) mit eigenen Probe-Programmen für die als "bestätigt" markierten
Befunde. Die Probes liegen nicht im Repository.

Markierung: **bestätigt** = durch Lauf unter ASAN bzw. Messung belegt oder
im Code eindeutig nachvollziehbar; **Verdacht** = aus dem Code abgeleitet,
nicht ausgeführt.

Übersicht
---------

| Nr. | Schweregrad | Status | Thema |
|-----|-------------|--------|-------|
| F1 | Hoch | bestätigt | Quadratische ClientHello-Verarbeitung durch Provider-ID-Deduplizierung (Remote-CPU-DoS) |
| F2 | Mittel | bestätigt | Use-after-free, wenn eine SSL_SESSION mit Provider-Cipher den OSSL_LIB_CTX überlebt; Designannahme zu EVP-Referenzen trifft nicht zu |
| F3 | Niedrig | bestätigt | Ein fehlerhafter Provider-Deskriptor oder eine Kollision zwischen Providern lässt jedes SSL_CTX_new() im Prozess scheitern |
| F4 | Niedrig | bestätigt | SSL_CIPHER_description() gibt bei langem Provider-Namen NULL statt gekürzter Ausgabe zurück |
| F5 | Info | Verdacht | Alert-Wahl bei nicht zulässiger externer PSK-Session |
| F6 | Info | Verdacht | `prov->libctx` wird auf den konkreten Kontext gepinnt (Semantikänderung) |
| F7 | Info | bestätigt | Teardown der Child-Owner-Provider: keine Speicherfehler gefunden, aber geänderte remove_cb-Semantik |

F1 – Quadratische ClientHello-Verarbeitung (Hoch, bestätigt)
------------------------------------------------------------

**Ort:** `ssl/ssl_lib.c:7685-7701` (`ossl_bytes_to_cipher_list`), dort
`ossl_ssl_cipher_stack_find(target, c)` für jede Provider-ID; Suchfunktion in
`ssl/ssl_ciph.c:244-260`.

**Begründung:** Für jeden Eintrag der ClientHello-Cipherliste, der auf eine
Provider-Suite aufgelöst wird, läuft eine lineare Suche über den bisher
aufgebauten Stack. Statische Suiten werden weiterhin unbegrenzt und ohne
Deduplizierung gepusht. Ein Angreifer sendet 16 383 statische IDs gefolgt von
16 383 Provider-IDs (65 532 Byte, das Maximum der cipher_suites-Liste). Jede
Provider-ID durchsucht dann rund 16 000 Einträge. Die Auflösung in
`ssl_provider_ciphersuite_by_char()` (`ssl/ssl_ciph.c:283-297`) geht gegen die
Registry von `session_ctx`; die Suite muss dafür nicht in der TLS-1.3-Liste
aktiviert sein. Es genügt, dass ein Provider mit `TLS-CIPHERSUITE`-Capability
im Kontext geladen ist.

Messung mit `SSL_bytes_to_cipher_list()` auf einem Server-SSL (32 766 Einträge):

| Build | nur statische IDs | halb statisch, halb Provider-ID |
|-------|-------------------|---------------------------------|
| `--release` (-O2) | 0,9 ms | 1107 ms |
| `enable-asan --debug` | 4 ms | 3340 ms |

Pro 64-KB-ClientHello also über eine Sekunde CPU auf einem Kern, ohne dass
der Client irgendeine Berechnung leisten muss. Die Designdoku sagt, das
Deskriptorlimit begrenze "registry storage and lookup"; die Kosten im
ClientHello-Parsing sind davon nicht abgedeckt.

**Fix-Vorschlag:** Deduplizierung entfernen (`ssl3_choose_cipher` und die
Abnehmer von `peer_ciphers` kommen mit Duplikaten zurecht, so wie bei
statischen Suiten), oder in O(1) deduplizieren, z. B. eine 8-KiB-Bitmap über
die 16-Bit-Code-Points auf dem Stack, die für jede gesehene Provider-ID
gesetzt wird. Zusätzlich einen Test mit einer maximal großen Liste aus
wiederholten Provider-IDs aufnehmen.

F2 – Session mit Provider-Cipher überlebt den OSSL_LIB_CTX (Mittel, bestätigt)
------------------------------------------------------------------------------

**Ort:** `ssl/t1_lib.c:433-452` und `:496-498` (fetch und Retention der
EVP-Objekte im Deskriptor), `ssl/ssl_ciph.c:146-165`
(`ossl_ssl_cipher_free` ruft `ssl_evp_cipher_free` → `EVP_CIPHER_get0_provider`),
`ssl/ssl_sess.c:986` (`SSL_SESSION_free`), `ssl/ssl_sess.c:131-146`
(Session hält eine gezählte Deskriptor-Referenz).

**Begründung:** Das Design (`doc/designs/provider-tls-ciphersuites.md:16-19`)
geht davon aus, dass die gehaltenen EVP-Objekte "die ausgewählte
Implementierung und ihre Provider-Referenzen" erhalten. In diesem Baum sind
`EVP_CIPHER_up_ref()`/`EVP_CIPHER_free()` für store-gecachte Fetches jedoch
No-ops (`crypto/evp/evp_enc.c:1583-1610`, `OPENSSL_NO_CACHED_FETCH` nicht
gesetzt). Die Lebensdauer der EVP-Objekte ist damit an den Method-Store des
OSSL_LIB_CTX gebunden, nicht an die Referenz des Deskriptors. Sobald eine
SSL_SESSION (oder ein per `SSL_SESSION_get0_cipher()` erhaltener Zeiger) den
Library-Kontext überlebt, zeigt `provider_cipher`/`provider_digest` auf
freigegebenen Speicher. Die Dokumentation in
`doc/man3/SSL_SESSION_get0_cipher.pod:24` ("remains valid after the
connection and SSL_CTX are freed") verleitet dazu, Sessions länger zu halten
als bisher nötig; vor dieser Änderung hat eine SSL_SESSION nie
kontextgebundene Objekte referenziert.

Reproduktion (ASAN): Handshake mit Provider-Suite, `SSL_get1_session()`,
SSL und beide SSL_CTX freigeben, Provider entladen, `OSSL_LIB_CTX_free()`,
danach `SSL_SESSION_free()`:

```text
ERROR: AddressSanitizer: heap-use-after-free
  #0 EVP_CIPHER_get0_provider crypto/evp/evp_lib.c:716
  #1 ssl_evp_cipher_free ssl/ssl_lib.c:7995
  #2 ossl_ssl_cipher_free ssl/ssl_ciph.c:160
  #3 SSL_SESSION_free ssl/ssl_sess.c:986
freed by: ossl_method_store_free <- context_deinit_objs crypto/context.c:308
```

Dieselbe Reihenfolge ohne vorheriges Entladen der Provider ergibt denselben
Fehler. Entladen des Providers bei lebendem Kontext (inkl. anschließendem
Fetch-Churn und Handshake) war dagegen unauffällig; das in
`test_provider_unload_lifetime` geprüfte Szenario hält.

**Fix-Vorschlag:** Kurzfristig die Lebensdauerregel explizit machen: in
`SSL_SESSION_get0_cipher.pod`, `SSL_get_ciphers.pod` und `provider-base(7)`
festhalten, dass Sessions und Deskriptoren aus Provider-Suiten vor
`OSSL_LIB_CTX_free()` freigegeben sein müssen, und die Designaussage zu
"provider references" korrigieren. Dazu einen Test aufnehmen, der genau diese
Reihenfolge prüft (`test_session_outlives_ctx` gibt nur das SSL_CTX frei).
Mittelfristig sollte die Session keine EVP-Objekte mehr besitzen, deren
Lebensdauer sie nicht kontrollieren kann: entweder nur Namen plus
Provider-Identität in der Session halten und erst bei Gebrauch gegen einen
lebenden Kontext auflösen, oder den Fetch mit echter Referenzzählung
(`EVP_CIPH_FLAG_NO_STORE`-Semantik) durchführen, damit `ossl_ssl_cipher_free`
ohne Zugriff auf den Store funktioniert.

F3 – Ein fehlerhafter Provider legt alle SSL_CTX lahm (Niedrig, bestätigt)
--------------------------------------------------------------------------

**Ort:** `ssl/t1_lib.c:509` (`callback_failed`), `:554-557`
(`discover_provider_ciphersuites` gibt 0 zurück), `:578-607`
(Code-Point- und Namenskollisionen in `index_provider_ciphersuites`),
`ssl/ssl_lib.c:4488-4491` (`SSL_CTX_new_ex` scheitert).

**Begründung:** Ein einziger ungültiger Deskriptor eines beliebigen geladenen
Providers (falscher Typ, Längenverstoß, GREASE-Code-Point, Namenskollision
mit einer eingebauten Suite) oder eine Kollision zwischen zwei Providern
führt dazu, dass im betroffenen Library-Kontext kein SSL_CTX mehr erzeugt
werden kann. Das ist laut `provider-base(7)` und `SSL_CTX_new.pod` so
gewollt, verschiebt aber die Verfügbarkeit von TLS in die Hand jedes per
Konfiguration geladenen Drittproviders. Nicht remote auslösbar.

**Fix-Vorschlag:** Deskriptoren des betroffenen Providers überspringen und
den Fehler nur in die Error-Queue bzw. den Trace schreiben; bei
Kollisionen deterministisch den ersten Eintrag behalten. Falls das Verhalten
bewusst beibehalten wird, sollte die CHANGES-Notiz den Effekt auf
`SSL_CTX_new()` deutlich nennen.

F4 – SSL_CIPHER_description() liefert NULL bei Kürzung (Niedrig, bestätigt)
---------------------------------------------------------------------------

**Ort:** `ssl/ssl_ciph.c:1942` und `:2154-2159`.

**Begründung:** Mit vom Aufrufer übergebenem Puffer (Länge ≥ 128) wurde die
Ausgabe bisher stillschweigend gekürzt. Jetzt führt `written >= len` zu
`NULL`. Provider-Namen dürfen 255 Zeichen lang sein und `enc` kommt aus
`EVP_CIPHER_get0_name()`, sodass der feste 128-Byte-Puffer vieler bestehender
Aufrufer (`char buf[128]; BIO_printf("%s", SSL_CIPHER_description(c, buf,
sizeof(buf)))`) nun NULL erhält. Innerhalb des Baums ist nur `apps/ciphers.c`
umgestellt; externe Aufrufer dereferenzieren typischerweise ungeprüft.

**Fix-Vorschlag:** Bei vorgegebenem Puffer weiterhin kürzen (snprintf-
Semantik) und NULL nur für `len < 128` bzw. Allokationsfehler zurückgeben,
oder die Änderung in `SSL_CIPHER_description.pod` und CHANGES dokumentieren.

F5 – Alert bei nicht zulässiger externer PSK-Session (Info, Verdacht)
---------------------------------------------------------------------

**Ort:** `ssl/statem/extensions_srvr.c:1394-1397`.

**Begründung:** Liefert `psk_find_session_cb` eine Session mit
Provider-Provenienz, sendet der Server `illegal_parameter` an den Client,
obwohl die Ursache eine lokale Konfiguration ist. Der Client kann daraus
nichts ableiten; `internal_error` wäre konsistent mit dem direkt davor
stehenden Callback-Fehlerpfad. Kein Sicherheitsproblem, nur Diagnostik.

F6 – `prov->libctx` auf den konkreten Kontext gepinnt (Info, Verdacht)
----------------------------------------------------------------------

**Ort:** `crypto/provider_core.c:680-681`.

**Begründung:** Bisher trug ein mit `libctx == NULL` geladener Provider
`NULL`, sodass `OSSL_FUNC_core_get_libctx()` und interne Fetches dynamisch
dem (thread-lokalen) Default folgten. Jetzt ist es der konkrete Kontext des
Provider-Stores. Für den Teardown ist das korrekt und `provfetchtest`
(Variante mit `OSSL_LIB_CTX_set0_default`) deckt es ab. Provider, die
`OSSL_FUNC_core_get_libctx()` mit `OSSL_LIB_CTX_set0_default()` kombinieren,
sehen ein anderes Verhalten. Sollte in CHANGES erwähnt werden.

F7 – Teardown der Child-Owner-Provider (Info, bestätigt)
--------------------------------------------------------

**Ort:** `crypto/provider_core.c:258-306`, `crypto/property/property.c:644-746`,
`crypto/context.c:280`.

**Begründung:** Die neue Reihenfolge (Child-Owner vor Decoder-/Encoder-/
Loader-/EVP-Store freigeben, Methoden des Owners zuvor ohne Locks aus den
Parent-Stores entfernen) wurde auf Double-Free und Use-after-free geprüft:
Der Provider wird vor dem Purge aus `store->providers` genommen, die
Store-Referenz bleibt bis `provider_deactivate_free()` erhalten, Cache-Aliasse
werden per Methodenidentität entfernt. Gegenüber dem bisherigen Pfad wird
`remove_cb` für das eigene Child des Owners nicht mehr aufgerufen, weil dessen
Callback vorher gelöscht wird. Das ist unkritisch, da Child-Provider im eigenen
Child-Kontext selbstreferenzierend sind und keine Referenz auf den Owner
halten (`crypto/provider_child.c:275-285`). Hinweis zur Vollständigkeit der
Fix-Absicht siehe "Nicht gemeldet".

Abgleich mit dem Designdokument
-------------------------------

Umgesetzt wie beschrieben: Discovery per Name/Property-Lookup; Registry nach
`SSL_CTX_new()` unveränderlich, sortierte Stacks, Namensindex;
Kanonisierung auf `session_ctx` inklusive Vergleich der EVP-Implementierung;
Session-Marker getrennt von `not_resumable`; Kopie geteilter Sessions
(Stateful-Ticket in `extensions_srvr.c:1517-1527`, externes PSK bereits
upstream kopiert, Client-Ticket in `statem_clnt.c:1813-1823`); Tickets werden
geparst und verworfen; `SSL_clear()` verwirft Provider-Sessions über
`ssl_clear_bad_session()`; kTLS, DTLS 1.3 und QUIC ausgeschlossen; HRR-Prüfung
über die Digest-Identität; 0-RTT wird bei abweichender Suite-ID abgelehnt
(`extensions_srvr.c:1584-1585`).

Abweichungen: Die Aussage zu erhaltenen Provider-Referenzen (F2) trifft im
Cached-Fetch-Modell nicht zu. Die Aussage, das Deskriptorlimit begrenze
"lookup", gilt nicht für das ClientHello-Parsing (F1).

Geprüft und ohne Befund
-----------------------

- Referenzzählung: `ossl_ssl_session_set1_cipher()`, `ssl_session_dup_intern()`
  (Cipher wird vor dem ersten Fehlerpfad auf NULL gesetzt), `SSL_SESSION_free()`,
  Registry-Freigabe in `SSL_CTX_free()`, `d2i_SSL_SESSION_ex()` im
  Wiederverwendungspfad (gespeicherte Referenz, Rollback bei Fehler).
- Capability-Parsing: exakte Längenprüfung der UTF8-Strings inklusive
  eingebetteter NULs, Integer-Breite ≤ 8 Byte, Code-Point 1..65535 ohne GREASE,
  Kollision mit statischen Tabellen und SCSVs, Namenszeichensatz, Limit 128.
- AEAD-Profil: AEAD-Flag, kein CCM, Blockgröße 1, IV 12, Tag 16,
  Schlüssellänge ≤ `EVP_MAX_KEY_LENGTH`, Secbits ≤ Schlüssellänge, Digest nur
  SHA-256/SHA-384 mit passender Größe.
- Statemachine: Ticket-Unterdrückung in beiden Transitionen, PHA-Pfad landet
  in derselben Verzweigung; `SSL_new_session_ticket()` lehnt ab;
  `tls_process_new_session_ticket()` validiert das Paket vollständig und stellt
  `max_early_data` wieder her; Längen vorab geprüft, kein Lesen über das Paket.
- PSK: externe Sessions mit Provider-Provenienz werden auf beiden Seiten
  abgewiesen, geteilte Sessions werden nicht mutiert.

Testlücken
----------

- T1 (zu F2): Kein Test, bei dem Session oder Deskriptor den OSSL_LIB_CTX
  überlebt; `test_session_outlives_ctx` gibt nur das SSL_CTX frei.
- T2 (zu F1): Kein Test mit großer, wiederholte Provider-IDs enthaltender
  Cipherliste; `test_provider_peer_list_deduplication` nutzt drei Einträge.
- T3: Kein End-to-End-0-RTT-Test (`SSL_write_early_data`/`SSL_read_early_data`)
  für Resumption eines eingebauten Tickets in eine Provider-Suite; abgedeckt
  sind nur Parser und Extension-Konstruktion.
- T4: Kein Test mit `SSL_verify_client_post_handshake()` auf einer
  Provider-Session (Ticket-Unterdrückung nach PHA). Verdacht, aus Code-Lesung
  unkritisch.
- T5: Kein Test für `SSL_set_SSL_CTX()` mit einem SSL_CTX aus einem anderen
  OSSL_LIB_CTX; das Design erklärt das für nicht unterstützt, ein
  Negativtest auf sauberes Scheitern (`NO_SHARED_CIPHER`) fehlt.

Nicht gemeldet (Upstream-Kontext)
---------------------------------

Ein Provider-Modul mit eigenem Child-Kontext, das per `OSSL_PROVIDER_load()`
geladen und vor `OSSL_LIB_CTX_free()` nicht entladen wird, erzeugt beim
Prozessende einen Use-after-free im thread-lokalen RAND-Zustand
(`rand_delete_thread_state` → `drbg_ctr_free` → `EVP_CIPHER_CTX_reset`).
Das reproduziert sich identisch mit demselben Modul gegen den Basis-Commit
41eecc7c und ist damit vorbestehend. Die neue Teardown-Logik (F7) ändert
daran nichts; falls der Commit "release child providers before parent method
stores" diesen Fall abdecken sollte, ist er nicht abgedeckt.
