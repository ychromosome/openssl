Best-Practice-Review: Provider-definierte TLS-1.3-Ciphersuites
==============================================================

Stand: `reviewtest` = 0bd50c5, Basis 41eecc7c; Autorenrückmeldung eingearbeitet (siehe Abschnitt "Disposition"). Dieser Report ergänzt
`SECURITY_REVIEW.md` um Konventionen, Wiederverwendung, Eigenentwicklungen,
API-Minimalismus, Teststruktur, Dokumentation und Commit-Aufbau. Sicherheit
wird hier nicht erneut bewertet.

Einstufung: **Empfehlung** = sollte vor dem Upstream-Review geändert werden,
**Konvention** = Abweichung von der Praxis im umgebenden Code, **Info** =
Beobachtung ohne Handlungsbedarf.

Werkzeuge und Ergebnisse
------------------------

| Prüfung | Ergebnis |
|---------|----------|
| `clang-format --style=file` (Projekt-`.clang-format`, WebKit-Stil; Projekt referenziert clang-format-21, hier 18.1.3) auf allen geänderten C-Dateien, verglichen mit der Basis | Keine neuen Abweichungen bis auf zwei Zeilen: Fortsetzungseinrückung in `crypto/provider_core.c:291-292` und eine Kommentareinrückung in `test/provider_tls_ciphersuite_test.c`. Alle anderen Differenzen bestehen bereits in der Basis. `util/check-format.pl` gibt es in 4.x nicht mehr. |
| `util/find-doc-nits -c -n -l` | Ohne Befund. Die History-Prüfung (`-i`, `-e`) ließ sich im Out-of-tree-Build nicht ausführen; die HISTORY-Abschnitte der neuen Doku wurden manuell geprüft und sind vorhanden. |
| `mdl -s util/markdownlint.rb` auf Design-Dokument, CHANGES.md, NEWS.md | Sauber. |
| `Assisted-by:`-Trailer nach CONTRIBUTING.md | In allen acht Commits vorhanden (20 Trailer). |
| Fehlercode `SSL_R_PROVIDER_CIPHERSUITE_SESSION_UNSUPPORTED:427` | Eindeutig; Header werden in 4.x beim Build erzeugt, `openssl.txt` genügt. |
| Neue öffentliche Symbole | Keine. Das Design-Ziel "no public function or ABI symbol" ist eingehalten. |

Befunde
-------

### B1 – Empfehlung: Doxygen-Kommentare an bestehenden Deklarationen im öffentlichen Header

**Ort:** `include/openssl/ssl.h.in` (20 neue `@brief`/`@see`-Blöcke, Basis: 0).

Kommentiert werden fast ausschließlich unveränderte, längst dokumentierte
Funktionen: `SSL_CTX_new_ex`, `SSL_CTX_free`, `SSL_CIPHER_get_handshake_digest`,
`SSL_get_shared_ciphers`, `SSL_CTX_set_ciphersuites`, `SSL_set_ciphersuites`,
`SSL_SESSION_set_cipher`, `SSL_SESSION_is_resumable`, `SSL_SESSION_free`,
`i2d_SSL_SESSION`, `SSL_set_session`, `SSL_CTX_add_session`,
`d2i_SSL_SESSION_ex`, `SSL_get1_supported_ciphers`, `SSL_new_session_ticket`,
`SSL_CIPHER_description`, `SSL_dup`, `SSL_CIPHER_find`,
`SSL_CIPHER_get_cipher_nid`, `SSL_CIPHER_get_digest_nid`. Inhalt ist jeweils
ein Satz plus Verweis auf die Manpage, also kein Mehrwert gegenüber der
Manpage selbst. Das ist Scope-Creep in einem Header, den jeder Nutzer einliest,
und erschwert die Review-Diff. In 4.x verwenden 35 `crypto/`- und 7
`ssl/`-Quelldateien Doxygen in `.c`-Dateien; öffentliche Header bleiben
kommentarlos.

**Vorschlag:** die Blöcke entfernen. Falls auf geänderte Semantik hingewiesen
werden soll (`SSL_SESSION_set_cipher` lehnt Provider-Suiten ab,
`SSL_CIPHER_find` kennt Provider-Suiten), gehört das in die Manpages, wo es
bereits steht.

### B2 – Empfehlung: Fetch ohne den vorhandenen libssl-Wrapper

**Ort:** `ssl/t1_lib.c:433` (`EVP_CIPHER_fetch`), Vergleich `ssl/ssl_lib.c:7948-7972`
(`ssl_evp_cipher_fetch`).

`ssl_load_ciphers()` holt alle Record-Cipher über `ssl_evp_cipher_fetch()`,
das decrypt-only-Implementierungen (`OSSL_CIPHER_PARAM_DECRYPT_ONLY`) als
unbrauchbar aussortiert. Die Discovery ruft `EVP_CIPHER_fetch()` direkt. Ein
decrypt-only-AEAD wird so als Suite registriert, angeboten und scheitert erst
beim Schlüsselaufbau mit `INTERNAL_ERROR`. Das ist dieselbe Klasse Prüfung, die
der Wrapper für die eingebauten Suiten übernimmt.

**Vorschlag:** `ssl_evp_cipher_fetch(ctx->libctx, aead_name, ctx->propq)`
verwenden; die `ERR_set_mark`/`ERR_pop_to_mark`-Klammer um den Fetch entfällt
dann, weil der Wrapper sie bereits enthält.

### B3 – Info: Eigene OSSL_PARAM-Helfer statt der API-Getter (korrigiert)

**Ort:** `ssl/t1_lib.c:276-310` (`tls_ciphersuite_get_string_param`),
`ssl/t1_lib.c:318-327` (`tls_ciphersuite_get_uint_param`). Vergleich:
`add_provider_groups` (`t1_lib.c:678-700`) und `add_provider_sigalgs`
(`t1_lib.c:850-871`).

- `tls_ciphersuite_get_uint_param` prüft `data_type`, `data == NULL`,
  `data_size == 0` und `data_size > 8` und ruft dann `OSSL_PARAM_get_uint()`.
  Korrektur gegenüber der ersten Fassung dieses Reports: Der Helfer ist nicht
  redundant. `OSSL_PARAM_get_uint32()` (`crypto/params.c:559-578`) akzeptiert
  neben `OSSL_PARAM_UNSIGNED_INTEGER` auch nichtnegative Werte vom Typ
  `OSSL_PARAM_INTEGER`; der Helfer erzwingt den in `provider-base(7)`
  festgelegten vorzeichenlosen Typvertrag. Redundant sind nur die NULL- und
  Größenprüfungen, was harmlos ist.
- `tls_ciphersuite_get_string_param` ist bewusst strenger als
  `OSSL_PARAM_get_utf8_string()` (exakte Länge, eingebettete NULs,
  Nachlaufdaten). Die Begründung im Commit ist nachvollziehbar und der
  Helfer sicherer als die Nachbarn, die `OPENSSL_strdup(p->data)` ohne
  Längenprüfung nutzen. Inkonsistent ist, dass drei Capabilities in derselben
  Datei drei Parser-Stile haben.

**Vorschlag:** Beide Helfer behalten. Den String-Helfer generisch benennen (etwa
`tls_capability_get_string`) und in einem Folge-Commit auch für TLS-GROUP und
TLS-SIGALG verwenden; alternativ als `ossl_param_get_utf8_string_exact()` in
`crypto/params.c` anbieten, damit Provider-Autoren dieselbe Semantik haben.

### B4 – Empfehlung: Doppelter Teardown-Code mit Neustart-Schleife

**Ort:** `crypto/property/property.c:644-746`
(`ossl_method_store_remove_all_provided_teardown`), Vergleich
`ossl_method_store_remove_all_provided` (`property.c:625-642`) und
`alg_cleanup_by_provider`.

Die neue Funktion wiederholt die Logik des bestehenden Entfernens ohne Locks
und ergänzt die Cache-Alias-Entfernung nach Methodenidentität. Die äußere
`for (;;)`-Schleife sucht pro Durchlauf eine einzelne Methode über alle Shards,
Cache-Listen und Archive und räumt sie dann wieder über alle Shards ab: für
einen Child-Owner mit M Methoden also M vollständige Store-Durchläufe. Für die
üblichen kleinen Provider ist das unkritisch, aber die Form ist unnötig
komplex und schwer zu reviewen.

**Vorschlag:** in einem Durchlauf alle Methodenzeiger des Providers in einen
Stack sammeln, dann Cache-Listen, Archiv und Implementierungen je einmal
durchlaufen. Oder `alg_cleanup_by_provider` um einen Parameter "ohne Locks,
inklusive Aliasse" erweitern, damit nur ein Codepfad existiert.

### B5 – Konvention: Namenspräfix `ossl_ssl_*`

**Ort:** 14 neue interne Funktionen in `ssl/ssl_local.h:2948-3140`.

Die Basis enthält zwölf `ossl_ssl_`-Vorkommen in `ssl_local.h`; die große
Mehrheit interner libssl-Funktionen heißt `ssl_*` oder `tls_*`
(`ssl_cipher_get_evp_cipher`, `ssl_session_dup`, `tls_use_ticket`). Die neuen
Namen sind in sich konsistent, verdoppeln aber die Präfixmenge.

**Vorschlag:** `ssl_`-Präfix wie die direkten Nachbarn. Das `ossl_`-Präfix ist
nur dort nötig, wo Symbole aus anderen Bibliotheksteilen sichtbar sein müssen;
die Tests linken statisch und sind kein Grund.

### B6 – Konvention: Linearer Tabellenscan für die Namenskollision

**Ort:** `ssl/s3_lib.c:4733-4753` (`ossl_ssl_has_cipher_name`).

Die Funktion scannt alle drei Tabellen nach `name` und `stdname`. Für
Stdnamen existieren `ssl3_get_cipher_by_std_name()` und
`ssl3_get_tls13_cipher_by_std_name()` direkt darunter (`s3_lib.c:4755-4785`);
für OpenSSL-Namen gibt es bisher keinen Lookup außerhalb des
Cipherlist-Parsers. Funktional ist die neue Funktion korrekt und läuft nur
bei `SSL_CTX_new()` je Deskriptor.

**Vorschlag:** als `ssl3_get_cipher_by_name()` neben die bestehenden Lookups
stellen und für den Stdnamen die vorhandene Funktion aufrufen, damit die
Tabellenlogik an einer Stelle bleibt.

### B7 – Konvention: Commit-Granularität

**Ort:** Commit 955a2e1 "ssl: negotiate provider suites with session ownership
guards": 42 Dateien, 4395 Zeilen, darunter Verhandlung, Session-Guards,
SNI-Semantik, kTLS-Ausschluss, drei Testprogramme und zwölf Manpages.

Die Commit-Botschaften sind gut und benennen Entscheidungen; die Größe des
Hauptcommits erschwert aber das Upstream-Review, das üblicherweise Commits um
wenige hundert Zeilen erwartet. Commit 8f55fb0 (Discovery, 2198 Zeilen)
besteht zu über 80 Prozent aus Tests und Testprovider.

**Vorschlag:** Aufteilung in Verhandlung (Auswahl, Kanonisierung),
Session-Regeln (Marker, Cache, Tickets, PSK), Record-Layer-Ausschlüsse,
Tests und Doku. Die Serie bleibt bisect-fähig, wenn jede Stufe für sich
kompiliert und die Tests der Stufe mitbringt.

### B8 – Konvention: Teststruktur und Testprovider

**Ort:** `test/provider_tls_ciphersuite_test.c` (2109 Zeilen),
`test/provider_tls_ciphersuite_ext_test.c` (1289), `test/provider_tls_nonresumption_test.c`
(432), `test/tls-provider.c` (+1117 Zeilen auf 4406).

- `make_pair`/`make_ctx_pair` und `exchange_data` sind in zwei Dateien nahezu
  identisch; `test/helpers/tls_provider.h` enthält bereits gemeinsame
  Helfer und wäre der Ort dafür.
- `tls-provider.c` trägt jetzt rund 40 per String ausgewählte Fixture-Modi
  (`tls_prov_get_ciphersuites`, 139 Zeilen, plus mehrere Tabellen). Das ist
  für ein Testprovider-Modul noch tragbar, aber die Capability-Fixtures haben
  mit dem XOR-KEM-Teil nichts zu tun. Eine eigene Datei
  `test/tls-provider-ciphersuites.c` würde beide Teile lesbar halten.
- Die Aufteilung in drei Programme folgt keiner erkennbaren Regel: `ext_test`
  und `nonresumption_test` nutzen beide interne Header, `ciphersuite_test`
  nicht. Zwei Programme (öffentliche API / interne API) wären klarer.
- Positiv: Wiederverwendung von `ssltestlib`, `threadstest.h`,
  `generate_ssl_tests.pl` und `ssl_test` für die Matrix; keine neuen
  Testframeworks.

### B9 – Info: Erweiterung von `struct ssl_cipher_st`

**Ort:** `ssl/ssl_local.h:493-497`.

Vier neue Felder in der Struktur aller statischen Cipher-Tabellen (Herkunft,
Refcount, zwei EVP-Zeiger). Die Alternative, ein Wrapper-Struct für
Provider-Deskriptoren, hätte `SSL_CIPHER *` an jeder API-Grenze unterscheiden
müssen. Die gewählte Lösung ist pragmatisch; der Speicherzuwachs ist
vernachlässigbar, und die statischen Initialisierer bleiben durch
Null-Initialisierung korrekt. `ossl_ssl_cipher_up_ref/free` casten `const`
weg, was dem Muster von `ssl_evp_cipher_free` entspricht.

### B10 – Info: Doxygen in internen Dateien

`ssl/ssl_local.h` (12 Blöcke, Basis 0), `ssl/t1_lib.c`, `ssl/ssl_ciph.c`,
`crypto/property/property.c`, `crypto/provider_core.c`. Das folgt dem in 4.x
begonnenen Trend und ist akzeptabel. Zwei Kleinigkeiten: die
`@brief`-Kommentare in `ssl_local.h` sind länger als die Funktionsnamen
erklären müssten, und `t1_lib.c:382` initialisiert `reason` mit einem Wert,
der nie gelesen wird (clang `deadcode.DeadStores`).

### B11 – Info: Build-Registrierung des Child-Moduls

**Ort:** `test/build.info:1410-1420`.

`tls-provider-child` wird außerhalb des `IF[!disabled{tls} && !disabled{tls1_3}]`-Blocks
registriert, in dem `tls-provider` liegt. Da `evp_extra_test2` `tls-provider.c`
ohnehin unbedingt kompiliert, bricht das keinen Build; es ist nur
inkonsistent zum Geschwistermodul. Der zugehörige Test
`04-test_provider_child_decoder.t` prüft korrekt nur `disabled("module")`.

Was gut gelöst ist
------------------

- Discovery folgt dem TLS-GROUP-Muster inklusive generiertem Parameter-Decoder
  (`ssl/t1_lib.inc.in`), statt einen eigenen Parser zu bauen.
- Sortierte OpenSSL-Stacks mit vorhandenen Vergleichern statt eigener
  Datenstrukturen; Registry unveränderlich nach Erzeugung.
- Keine neue öffentliche API; alle Verhaltensänderungen über bestehende
  Funktionen dokumentiert, mit HISTORY-Einträgen, CHANGES und NEWS.
- Fehlerbehandlung an öffentlichen Grenzen (`NULL`-Argumente, Allokation) und
  transaktionale Setter (`SSL_set_ciphersuites` ändert erst nach Erfolg).
- Testabdeckung breit, mit Negativfällen für jedes Parameterfeld, Nebenläufigkeit
  und CLI-Durchstich.

Priorisierung
-------------

1. B2 (Fetch-Wrapper): kleine Änderung mit fachlichem Nutzen.
2. B1 (Header-Kommentare) und B7 (Commit-Aufteilung): erhöhen die Chance auf
   ein zügiges Upstream-Review deutlich.
3. B4, B5, B6, B8: Pflegeaufwand, am besten vor dem ersten Upstream-PR, danach
   teuer.
4. B9 bis B11: zur Kenntnis.

Disposition nach Autorenrückmeldung
-----------------------------------

| Befund | Entscheidung des Autors | Anmerkung des Reviews |
|--------|-------------------------|-----------------------|
| B1 | übernommen | – |
| B2 | übernommen, mit Negativtest (`OSSL_CIPHER_PARAM_DECRYPT_ONLY`) | Der Digest-Fetch braucht weiterhin eine eigene `ERR_set_mark`-Klammer, da es keinen `ssl_evp_md_fetch`-Wrapper gibt. |
| B3 | abgelehnt | Review korrigiert: Typvertrag macht den uint-Helfer nicht redundant. |
| B4 | vorerst keine Änderung | Begründung (keine Allokation im Teardown) nachvollziehbar. |
| B5, B6, B11 | keine Änderung | Akzeptiert. |
| B7, B8 | zurückgestellt bis zur Maintainer-Vorgabe | Akzeptiert. |
| B9 | zur Kenntnis | – |
| B10 | teilweise übernommen (`reason`-Initialisierung) | – |
