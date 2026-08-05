# tarpitd

SMTP tarpit dla FreeBSD, w duchu `spamd(8)` z OpenBSD, ale bez własnej listy —
o tym, kto jest spammerem, decyduje tabela IPFW, którą już wypełnia fail2ban.
`tarpitd` odbiera przekierowany tam ruch i trzyma go tak długo, jak się da.

Nic nigdy nie zostaje przyjęte i nic nigdy nie zostaje odrzucone na stałe:
każda odpowiedź kończąca transakcję to `4xx`, więc wiadomość zostaje w kolejce
nadawcy i wraca do nas później. Celem nie jest szybkie odrzucenie poczty, tylko
zajęcie slotu w kolejce botnetu na wiele godzin.

## Jak to działa

Cała sztuczka to bycie **wolnym, ale poprawnym**. Każda odpowiedź jest
składniowo prawidłowym SMTP-em, więc nadawca nie ma powodu się rozłączyć — tyle
że wychodzi po jednym bajcie, a komendy są czytane w tym samym tempie.

| Trik | Co robi |
|---|---|
| Greeting delay | Przez `-g` sekund po `accept()` nie leci nic. |
| Stuttering | Bajt na `-S` ms w obie strony. Bufor nadawczy spammera nigdy się nie opróżnia, jego `write()` blokuje. |
| Niekończący się banner | Wielolinijkowe `220-`. Klient zgodny z RFC **musi** czekać na `220 `, a przy `-b 0` ta linia nie przyjdzie nigdy. |
| Wykrywanie early talkerów | SMTP to server-speaks-first — nic legalnego nie odzywa się przed końcem powitania. Kto to robi, dostaje banner bez końca i podwójne opóźnienia. |
| Pompowanie EHLO | `-e` dodatkowych nieznanych rozszerzeń, które klient musi przeczytać i zignorować. |
| Fałszywy STARTTLS | Nagłówek rekordu TLS z `ServerHello` o długości 16376 B i sączenie losowych bajtów. Biblioteka TLS klienta zobowiązała się przeczytać całą wiadomość handshake, zanim zrobi cokolwiek innego — łącznie z timeoutem na poziomie SMTP. Po skończeniu rekordu zaczyna się następny. |
| Honeypot AUTH | Oferujemy `PLAIN`/`LOGIN`/`CRAM-MD5`, dekodujemy base64, logujemy i odpowiadamy `535` — niech próbuje dalej. |
| Malutkie okno TCP | `SO_RCVBUF`/`SO_SNDBUF` = `-w` bajtów. Spammer ma w locie kilkaset bajtów i tyle. To samo trzyma nasze zużycie pamięci jądra przy tysiącach sesji. |
| Parkowanie w backlogu | Po osiągnięciu `-c` połączeń przestajemy `accept()`ować zamiast odrzucać. Nadmiar wisi w kolejce jądra — nadawca uważa, że jest połączony, a nas nie kosztuje ani jednego deskryptora. |
| Ramping opóźnień | Opóźnienie podwaja się co `-R` sekund do `-M`. Kto wytrzymał godzinę, jest cierpliwy i można go trzymać niemal za darmo. Wszystkie opóźnienia są jitterowane, żeby czas nie był fingerprintem. |

Dla domyślnych ustawień (1 bajt / 1,5 s) samo `EHLO` to około 40 minut, a pełna
próba dostarczenia wiadomości — godziny.

## Budowanie i instalacja

```sh
make
make install          # /usr/local/sbin/tarpitd + man + rc.d
```

Opcjonalnie:

```sh
make WITH_CAPSICUM=yes   # workery wchodzą w capability mode po bind()
make DEBUG=yes
```

Wymaga tylko bazowego systemu (`kqueue`, `libutil`).

## ipfw

Zakładam, że fail2ban wrzuca adresy do tabeli 22. Przekierowanie na tarpit:

```sh
ipfw table 22 create type addr valtype skipto     # jeśli jeszcze nie istnieje
ipfw add 1000 fwd 127.0.0.1,8025 tcp from "table(22)" to me 25 in
```

Reguła `fwd` z lokalnym adresem powoduje dostarczenie pakietu lokalnie na
wskazany port; nagłówki się nie zmieniają, więc `getsockname()` w tarpicie
nadal widzi **oryginalny adres docelowy** — dlatego w logu przy każdej sesji
jest zapisane, pod który z Twoich adresów bot się dobijał.

Dla IPv6:

```sh
ipfw add 1001 fwd ::1,8025 tcp from "table(22)" to me6 25 in
tarpitd -l 127.0.0.1:8025 -l "[::1]:8025"
```

Sprawdź, czy `net.inet.ip.fw.one_pass` nie psuje reszty Twojego zestawu reguł —
przy `one_pass=1` (domyślnie) pakiet po `fwd` nie wraca do dalszych reguł.

Włączenie:

```sh
sysrc tarpitd_enable=YES
sysrc tarpitd_maxconn=8192
service tarpitd start
```

Zmienne rc.conf:

| Zmienna | Domyślnie | Znaczenie |
|---|---|---|
| `tarpitd_enable` | `NO` | |
| `tarpitd_listen` | `127.0.0.1:8025` | adres nasłuchu |
| `tarpitd_maxconn` | `4096` | limit równoległych sesji |
| `tarpitd_runas` | `nobody` | użytkownik po zrzuceniu uprawnień |
| `tarpitd_pidfile` | `/var/run/tarpitd.pid` | |
| `tarpitd_flags` | — | dodatkowe opcje, np. `-v` |

**Użytkownik to `tarpitd_runas`, nie `tarpitd_user`.** `${name}_user` to zmienna
zarezerwowana przez rc.subr, która uruchamia całość przez `su` — wtedy demon
startuje od razu jako `nobody`, nie może zapisać pidfile'a ani zbindować portu
uprzywilejowanego, a `setgroups()` w zrzucaniu uprawnień kończy się `EPERM`.

Podgląd na żywo, bez demonizacji:

```sh
tarpitd -d -v -v -l 127.0.0.1:8025 -u ""
```

## Tuning jądra pod tysiące trzymanych połączeń

Każde złapane połączenie to jeden deskryptor i jedno gniazdo przez wiele godzin.
Przy `-c 8192` w `/etc/sysctl.conf`:

```
kern.ipc.maxsockets=65536
kern.maxfiles=131072
net.inet.tcp.syncache.hashsize=2048
net.inet.tcp.syncache.bucketlimit=100
```

`rc.d/tarpitd` sam podnosi limit deskryptorów procesu do `tarpitd_maxconn + 128`.
Jeśli twardy limit na to nie pozwala, demon obniża `-c` i zapisuje to w logu.

Warto też zostawić `net.inet.tcp.blackhole=0` na porcie tarpita — chcemy, żeby
handshake się udawał, inaczej nie ma kogo trzymać.

## Statystyki

`SIGINFO` (Ctrl-T na terminalu) albo `SIGHUP` wypisuje podsumowanie; to samo
leci do sysloga co godzinę:

```
stats: active=1832 peak=2140 total=41991 refused=88 wasted=3106h12m \
       bodies=903 auth=2214 tls=771 cmds=88410 rx=1104882 tx=48221904
```

`wasted` to sumaryczny czas połączeń — jedyna metryka, która się tu liczy.

## Logi

Przy `-v` do `syslog` (facility `mail`) trafiają otwarcia i zamknięcia sesji
z podsumowaniem, koperty i zebrane poświadczenia:

```
open 203.0.113.9:41022>198.51.100.4:25 (312 active)
early talker 203.0.113.9:41022>198.51.100.4:25, greeting will not end
mail 203.0.113.9:41022>198.51.100.4:25 from=<bounce@spam.example>
auth 203.0.113.9:41022>198.51.100.4:25 LOGIN user=admin
auth 203.0.113.9:41022>198.51.100.4:25 LOGIN pass=P@ssw0rd123
starttls 203.0.113.9:41022>198.51.100.4:25 entering handshake stall
close 203.0.113.9:41022>198.51.100.4:25 held=27431s cmds=14 rcpt=3 body=0 \
      rx=241 tx=39122 early-talker (session limit)
```

Wszystko, co przyszło od zdalnej strony, jest przepuszczane przez sanityzację
przed zapisem — żadnych znaków sterujących ani wstrzykiwania linii do logu.
`-L` wyłącza logowanie kopert i haseł, jeśli nie chcesz ich trzymać.

## Ostrzeżenie

Nie kieruj tu ruchu, którego wcześniej nie zaklasyfikowałeś jako wrogi.
`tarpitd` jest nieodróżnialny od zepsutego serwera pocztowego — legalny nadawca,
który tu trafi, będzie ponawiał aż do wygaśnięcia swojej kolejki, a potem
odbije wiadomość do nadawcy.

## Struktura

```
tarpitd.c    pętla zdarzeń kqueue, gniazda, limity, uprawnienia, workery
smtp.c       maszyna stanów dialogu SMTP i generatory odpowiedzi
tarpitd.h    wspólne deklaracje
rc.d/tarpitd skrypt startowy
tarpitd.8    strona podręcznika
```
