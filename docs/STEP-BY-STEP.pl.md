# Krok po kroku: logowanie kartą na nowym Debianie 13

Proste instrukcje, po kolei. Każde polecenie wpisujesz **na nowej maszynie
z Debianem 13**, chyba że krok mówi inaczej. Wersja angielska:
[STEP-BY-STEP.md](STEP-BY-STEP.md).

Są dwie drogi:

* **Droga A — skopiuj maszynę, która już działa.** Najszybciej. Kroki 1–2, potem A1–A4.
* **Droga B — konfiguracja od zera.** Kroki 1–2, potem B1–B6.

Potem dla obu: krok 9 (test) i, jeśli to obraz wzorcowy Horizon, krok 10.

---

## Gdzie co wrzucić

| Co | Gdzie położyć na nowej maszynie | Kto tego używa |
|---|---|---|
| `sssd-smartcard_<wersja>_all.deb` (to narzędzie) | dowolny folder, np. `/root/` lub `/tmp/` | `apt-get install ./…deb` |
| Kopia konfiguracji ze starej maszyny (`*.tar.gz`) | `/root/` | `sssd-smartcard-capture --replay` |
| Certyfikaty CA (główny i wystawiający, `.pem`) | `/root/pki/` — **tylko** jeśli narzędzie nie pobierze ich samo | `sssd-smartcard-setup --ca …` |
| Ustawienia tej maszyny | `/etc/sssd-smartcard/environment.json` (zapisywany za Ciebie) | wszystkie skrypty |
| Agent Horizon `Omnissa-horizonagent-linux-x86_64-*.tar.gz` | `/opt/vdi-imagemaint/Horizon/` | `vdi-imagemaint.sh agent` (krok 10) |
| Agent nagrywania `Horizon.Recording.Linux.Agent-*.tar.gz` (opcjonalnie) | `/opt/vdi-imagemaint/Horizon/` | `vdi-imagemaint.sh recording` |
| Certyfikaty CA dla True SSO na obrazie Horizon | `/opt/vdi-imagemaint/certs/` | `vdi-imagemaint.sh domain` |
| Pomocnik dla Windows `sssd-smartcard-windows-<wersja>.zip` | na komputerze z **Windows**, dowolny folder | SSH kartą z Windows (krok 9) |

**Nigdy** nie kopiujesz między maszynami: `/etc/krb5.keytab`, `/var/lib/sss/`,
kluczy prywatnych. Każda maszyna dołącza do domeny pod własną nazwą.

---

## 1. Przygotuj Debiana 13

Zaloguj się jako `root` (albo `su -`). Świeży Debian nie ma `curl`, często nie ma też `sudo`:

```bash
apt-get update && apt-get install -y curl ca-certificates sudo python3
```

Nadaj maszynie docelową nazwę teraz. Zmiana nazwy po dołączeniu do domeny sprawia kłopoty:

```bash
hostnamectl set-hostname nowy-host
```

## 2. Zainstaluj narzędzie

```bash
VER=0.3.0
cd /root
curl -sSfLO "https://github.com/franekSoftSF/sssd-smartcard-Profile-Manager/releases/download/v$VER/sssd-smartcard_${VER}_all.deb"
curl -sSfLO "https://github.com/franekSoftSF/sssd-smartcard-Profile-Manager/releases/download/v$VER/sssd-smartcard_${VER}_all.deb.sha256"
sha256sum -c "sssd-smartcard_${VER}_all.deb.sha256"
```

Musi pojawić się `OK`. Potem:

```bash
apt-get install -y "./sssd-smartcard_${VER}_all.deb"
sssd-smartcard --version
```

---

## Droga A — skopiuj maszynę, która już działa

### A1. Pobierz konfigurację ze starej maszyny

Wpisz to na nowej maszynie. Zamień `admin@stary-host` na swoje konto i nazwę
starej maszyny. Zostaniesz zapytany o hasło SSH i hasło `sudo` na starej maszynie:

```bash
cd /root
sssd-smartcard-capture --from admin@stary-host --out stary-host.tar.gz
```

Na starej maszynie nic się nie zmienia. Hasła, keytaby i klucze prywatne nigdy
nie są kopiowane.

Zobacz, co zostało pobrane:

```bash
sssd-smartcard-capture --show stary-host.tar.gz
```

### A2. Pierwsze odtworzenie: zapisuje plik ustawień

```bash
sssd-smartcard-capture --replay stary-host.tar.gz
```

Zapisuje `/etc/sssd-smartcard/environment.json` i zatrzymuje się, bo ta
maszyna nie jest jeszcze w domenie. Otwórz plik i sprawdź dwie linie:

```bash
nano /etc/sssd-smartcard/environment.json
```

* `"hostname"` — nazwa **tej** maszyny;
* `"join_user"` — konto AD, które może dodawać komputery do domeny.

### A3. Dołącz do domeny

```bash
ad-prepare --yes
sssd-smartcard-setup --only packages,join,identity --yes
```

Pierwsze polecenie ustawia DNS i nazwę hosta. Drugie instaluje pakiety i dołącza
do domeny; zapyta o hasło konta `join_user`.

### A4. Odtwórz jeszcze raz: najpierw obejrzyj, potem zastosuj

Obejrzyj (nic się nie zmienia):

```bash
sssd-smartcard-capture --replay stary-host.tar.gz
```

Otwórz teraz **drugą sesję root** (drugie okno SSH albo konsolę) i jej nie
zamykaj. Jeśli coś pójdzie nie tak z logowaniem, masz jeszcze tę. Potem zastosuj:

```bash
sssd-smartcard-capture --replay stary-host.tar.gz --yes --pam
```

Na końcu jest lista **„Not reproduced automatically — review”** (nie odtworzono
automatycznie — przejrzyj). Każda linia to plik, który tutaj jest inny, i
polecenie `diff -u`, żeby go porównać. Przeczytaj; przenieś tylko to, co rozumiesz.

Przejdź do **kroku 9**.

---

## Droga B — konfiguracja od zera

### B1. Opisz domenę jeden raz

```bash
ad-prepare --init-env --domain ad.example.com
nano /etc/sssd-smartcard/environment.json
```

Uzupełnij `join_user` (kto może dodawać komputery) i `test_user` (użytkownik
z kartą, np. `ktos@ad.example.com`). Dla pełnej konfiguracji ustaw też:

```json
  "crl": true,
  "ssh": true,
  "sudo_group": "linux-admins@ad.example.com",
  "sudo_agent": true,
  "mkhomedir": true,
```

`sudo_group` to grupa w AD; jej członkowie dostają `sudo`. Zostaw `""`, jeśli tego nie chcesz.

### B2. DNS, nazwa hosta, dołączenie do domeny

```bash
ad-prepare --yes
sssd-smartcard-setup --only packages,join,identity --yes
```

### B3. Włóż kartę do czytnika i pozwól narzędziu znaleźć PKI

```bash
sssd-smartcard ca discover --from-card
```

Porównaj wypisane odciski (`SHA-256`) z tymi, które daje Twój zespół PKI.
Jeśli się zgadzają:

```bash
sssd-smartcard ca discover --from-card --install
```

Jeśli narzędzie nie może pobrać certyfikatów CA, skopiuj je do `/root/pki/` i
dopisz w pliku ustawień: `"ca": ["/root/pki/root-ca.pem", "/root/pki/issuing-ca.pem"]`.

### B4. Sprawdź nazwę użytkownika na karcie

```bash
sssd-smartcard cert inspect --from-card
```

Przeczytaj linię `Domain:`. Jeśli różni się od Twojej domeny AD, to normalne
(alternatywny sufiks UPN) — narzędzie sobie z tym radzi.

### B5. Obejrzyj plan

```bash
sssd-smartcard-setup --dry-run
```

Nic się nie zmienia. Przeczytaj kolejne etapy.

### B6. Zastosuj

Otwórz **drugą sesję root** i jej nie zamykaj. Potem:

```bash
sssd-smartcard-setup --yes --pam
```

To zapisuje `sssd.conf`, listę CRL i jej codzienne odświeżanie, SSH kartą,
regułę `sudo` i ustawienia PAM. Każdy krok sam się sprawdza; jeśli któryś się
nie uda, wszystko z tego uruchomienia jest przywracane.

---

## 9. Test (obie drogi)

Z kartą w czytniku. Musi zapytać o **PIN**, nie o hasło:

```bash
pamtester -v login ktos@ad.example.com authenticate acct_mgmt
```

Sprawdź wszystko naraz:

```bash
sssd-smartcard doctor --user ktos@ad.example.com
```

Reguły `sudo` użytkownika (sprawdzenie nie wymaga hasła):

```bash
sudo -l -U ktos@ad.example.com
```

Klucze SSH, które serwer bierze z certyfikatu na karcie:

```bash
sss_ssh_authorizedkeys ktos@ad.example.com
```

**Z Windows:** rozpakuj `sssd-smartcard-windows-<wersja>.zip` i uruchom skrypt
ze środka w PowerShell; sprawdza PuTTY-CAC i kartę, i wypisuje polecenie do
połączenia. Szczegóły: [windows-smartcard-ssh.pl.md](windows-smartcard-ssh.pl.md).

Jeśli coś nie działa, zbierz raport i wyślij go:

```bash
sssd-smartcard debug bundle
```

---

## 10. Tylko dla obrazu wzorcowego Horizon VDI (VDI-ImageMaint)

Część Horizon robi drugie narzędzie, VDI-ImageMaint, które mieszka w
`/opt/vdi-imagemaint/`. Kolejność ma znaczenie:

1. Zainstaluj VDI-ImageMaint:

   ```bash
   wget -qO- https://github.com/franekSoftSF/horizon-scripts/releases/latest/download/get-vdi-imagemaint.sh | sudo bash
   ```

2. Skopiuj pliki (z komputera przez WinSCP albo z pendrive’a):
   * `Omnissa-horizonagent-linux-x86_64-*.tar.gz` → `/opt/vdi-imagemaint/Horizon/`
     (pobierz z Omnissa Customer Connect; Debian 13 wymaga agenta **2606 lub nowszego**);
   * opcjonalnie `Horizon.Recording.Linux.Agent-*.tar.gz` → `/opt/vdi-imagemaint/Horizon/`;
   * certyfikaty CA dla True SSO → `/opt/vdi-imagemaint/certs/`.

   Źródła sterownika USB 3.0 (`vhci-hcd-1.15.tar.gz`) instalator pobiera sam.

3. Uruchom **najpierw** VDI-ImageMaint — `prepare`, `domain`, `agent` (zobacz
   jego instrukcję, `docs/pl/linux.md` w horizon-scripts).
4. **Potem** uruchom to narzędzie (Droga A albo B powyżej) — reguły karty, CRL, SSH i sudo.
5. Test (krok 9), potem `vdi-imagemaint.sh seal`.

Dwie zasady:

* `vdi-imagemaint.sh domain` nadpisuje `sssd.conf`. Jeśli kiedyś uruchomisz go
  ponownie, potem uruchom jeszcze raz `sssd-smartcard-setup --yes`.
* Zaplombowany obraz (seal) nie pozwala instalować pakietów. Zainstaluj lub
  zaktualizuj to narzędzie **przed** `seal` albo najpierw uruchom `vdi-imagemaint.sh unlock`.

---

## Cofanie zmian

* Konfiguracja z jednego uruchomienia: kopie zapasowe są w `/var/lib/sssd-smartcard/backups/<data>/`.
* Pliki `sudo` i SSH zapisane przez narzędzie: `/etc/sudoers.d/90-sssd-smartcard-admins`,
  `/etc/sudoers.d/91-sssd-smartcard-ssh-agent`, `/etc/ssh/sshd_config.d/60-sssd-smartcard.conf`.
* Całkowite opuszczenie domeny: `ad-reset --yes`.
