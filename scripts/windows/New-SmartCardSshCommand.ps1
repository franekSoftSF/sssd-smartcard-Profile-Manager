<#
.SYNOPSIS
    Checks whether this Windows workstation can do SSH public-key authentication
    with a PIV smart card, and prints the PuTTY-CAC command line to use.

.DESCRIPTION
    This script is read-only. It inspects the workstation, reports each
    prerequisite as PASS / WARN / FAIL with a one-line remedy, and then prints a
    command for you to run yourself.

    It never launches PuTTY, never downloads anything, never installs a driver,
    never touches a private key, and never asks for, stores or logs a PIN. The
    checks do not need administrator rights; only the suggested remedies
    (installing a minidriver) do.

    Why PuTTY-CAC and not OpenSSH:

      * C:\WINDOWS\System32\OpenSSH\ssh.exe (OpenSSH_for_Windows_9.5p2) accepts
        -I <pkcs11> and then silently ignores it -- PKCS#11 support is compiled
        out of that build. Even with -vvv it prints no provider or dlopen line.
        It cannot do card authentication, and this script never suggests it.
      * The ssh.exe shipped with Git for Windows does implement PKCS#11, but
        loading a native opensc-pkcs11.dll into that MSYS2 binary crashes
        reproducibly. Not suggested either.

    So PuTTY-CAC is the supported client. Its certificate syntax is
    "-i CAPI:<sha1-thumbprint>" for the Windows certificate store, or
    "-i PKCS:<id>=<path-to-pkcs11.dll>" for a PKCS#11 module.

    Three traps this script exists to catch:

      1. PuTTY-CAC offers x509v3-ssh-rsa (RFC 6187) when X.509 mode is on.
         OpenSSH does not implement that algorithm and refuses the key with
         "unsupported public key algorithm"; the client only shows you
         "Server refused our key". So -x509off is always emitted below.
         X.509 mode is a persistent, global PuTTY-CAC setting shared with
         Pageant, which is why passing -x509off every time is worth doing.
      2. The thumbprint must come from the card, not from the Windows
         certificate store. A store entry can point at a key container that no
         longer exists -- Windows then says "the smart card cannot perform the
         requested operation or the operation requires a different smart card",
         which is literally true. Stale entries accumulate; a workstation that
         has enrolled a few cards can easily have more dead entries than live
         ones, several of them sharing one subject name.
      3. Therefore the single most useful check here compares the key container
         that the store entry names against the containers actually present on
         the card. If they differ, that certificate is unusable, whatever the
         store says about it.

    Any PIV token that Windows exposes through a smart card minidriver works.
    Yubico YubiKey and HID Crescendo are recognised by name so that the script
    can name the right minidriver if one is missing; an unrecognised token is
    still read, still checked and still gets a command line -- the script simply
    says it does not know which minidriver that vendor needs.

.PARAMETER User
    The login name to send to the server, e.g. someone@ad.example.com. It is
    emitted with PuTTY's -l switch rather than as user@host, because Active
    Directory UPNs contain an '@' and user@host parsing would split on it.

.PARAMETER ComputerName
    The SSH server to connect to, e.g. linux-host.ad.example.com.

.PARAMETER Port
    SSH port. Defaults to 22.

.PARAMETER PuttyPath
    Full path to putty.exe, overriding discovery. Use this when PuTTY-CAC is
    installed somewhere unusual, or when both stock PuTTY and PuTTY-CAC are
    installed and discovery picks the wrong one.

.PARAMETER Thumbprint
    Use this certificate SHA-1 thumbprint instead of choosing one from the
    card. Also the way to resolve an ambiguous choice when more than one token
    is attached.

.PARAMETER Reader
    Restrict discovery to readers whose name contains this text, e.g. -Reader
    YubiKey. The other way to resolve an ambiguous choice.

.PARAMETER UseOpenSC
    Also read the thumbprint straight off the card with OpenSC's pkcs11-tool,
    as a cross-check of what certutil reports. Reads only public certificate
    objects; no PIN is needed or requested.

.PARAMETER ForwardAgent
    Add -A (agent forwarding) to the emitted command, and check the two
    client-side things that agent-forwarded sudo needs: that Pageant is
    running, and that the saved session has agent forwarding enabled.

    This lets sudo on the Linux host authenticate against the card even though
    the card is here on Windows: pam_ssh_agent_auth verifies a signature from
    the forwarded agent.

    It has a real cost. Read the security note that the script prints, and the
    NOTES section below. (Careful: a line inside comment-based help that begins
    with a dot and a keyword name is parsed as a new help section, which is why
    that word is bare here.)

.PARAMETER Language
    Output language: en (default) or pl.

    Technical identifiers are never translated -- option names, registry paths,
    command lines, CAPI:, and anything quoted verbatim from Windows, OpenSSH or
    certutil. Only the prose around them changes, so a command you copy out of
    Polish output is the same command.

    A message with no Polish translation prints in English rather than blank,
    so an English line among Polish ones means exactly that and nothing worse.
    Run with -SelfTest to list any such gaps.

.PARAMETER SelfTest
    Check the message catalogue and exit: every message must have either a
    Polish translation or an explicit EnglishOnly marker. Prints a per-language
    count and the ids of anything missing. Exits 0 when the catalogue holds,
    1 when it does not. Touches nothing else.

.PARAMETER Launch
    Apply the per-user configuration this run found necessary, re-check it by
    reading it back, and then start PuTTY with the command line below.

    Every change is reported as it is made, together with the command that
    reverses it, and a summary of those reverse commands is printed at the end.

    What it will apply, all per-user and all reversible: values under
    HKCU\Software\SimonTatham\PuTTY (AuthX509, AutoloadCerts, SaveCertList), the
    per-session AgentFwd and TryAgent when -SessionName was given, the Startup
    shortcut, loading the certificate into Pageant, and registering the card
    certificate in your own store.

    What it will NOT do, by design:

      * Install software. winget downloads, installs and usually needs
        elevation, and that is a change to the machine rather than to your
        configuration. If something is missing, -Launch stops before connecting
        and prints the install command for you to run.
      * Anything needing administrator rights. It fails loudly instead of
        prompting for elevation.
      * Write a PIN anywhere, or pass -forcepincache.

    Without -Launch nothing is applied and the script only prints.

.PARAMETER SessionName
    A saved PuTTY session name. With -ForwardAgent, the script reads that
    session's AgentFwd and TryAgent registry values and reports them, with the
    exact "reg add" to fix either one. Without it, the per-session settings
    cannot be checked -- only Pageant itself.

.EXAMPLE
    .\New-SmartCardSshCommand.ps1 -User someone@ad.example.com -ComputerName linux-host.ad.example.com

    Run the checks and print the putty.exe and plink.exe command lines.

.EXAMPLE
    .\New-SmartCardSshCommand.ps1

    Run the checks only. Without -User and -ComputerName the script reports
    what it found and shows the command shape with placeholders.

.EXAMPLE
    .\New-SmartCardSshCommand.ps1 -User someone@ad.example.com -ComputerName linux-host.ad.example.com -Reader YubiKey

    Same, but only consider the token in the reader whose name contains
    "YubiKey". Use this when several tokens are attached at once.

.EXAMPLE
    .\New-SmartCardSshCommand.ps1 -User someone@ad.example.com -ComputerName linux-host.ad.example.com -ForwardAgent -SessionName my-linux-host

    Also check the client side of agent-forwarded sudo and add -A to the
    emitted command. -SessionName names a saved PuTTY session whose AgentFwd
    and TryAgent values are then reported.

.NOTES
    Read-only by nature, so there is nothing for -WhatIf to suppress: the
    script changes no state and starts no connection. Use -Verbose to see the
    external commands it runs.

    The server side is assumed to be configured already: SSSD derives the SSH
    public key from the X.509 certificate on the card, and sshd fetches it via
    AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys. Nothing has to be
    copied to the server, and certificate revocation therefore covers SSH too.

    Agent forwarding (-ForwardAgent) extends that to sudo, via
    pam_ssh_agent_auth with authorized_keys_command pointed at the same
    sss_ssh_authorizedkeys. Keys therefore come from the same AD source sshd
    uses, so revoking the certificate removes sudo access too -- which is the
    whole point, and the reason not to paste a key into ~/.ssh/authorized_keys
    as most guides suggest. A key pasted there survives revocation and silently
    undoes it.

    The cost of -A: while the session is alive, anyone with root on that server
    can use the forwarded agent to authenticate AS YOU to other hosts. The
    agent signs whatever it is asked to sign, and root on the far end can reach
    the forwarded socket. Enable it per session, for hosts you trust with your
    identity -- never as "Host *" in a config.

    See docs/windows-smartcard-ssh.pdf in this repository for the long form.
#>

# NB: #Requires must come *after* the comment-based help block. A #Requires
# statement ahead of it stops Get-Help finding the help at all -- verified both
# ways on PowerShell 5.1 and 7.
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string] $User,
    [string] $ComputerName,
    [int]    $Port = 22,
    [string] $PuttyPath,
    [string] $Thumbprint,
    [string] $Reader,
    [switch] $UseOpenSC,
    [switch] $ForwardAgent,
    [string] $SessionName,
    [switch] $Launch,
    [ValidateSet('en', 'pl')] [string] $Language = 'en',
    [switch] $SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# Set before anything is printed, because T reads it.
$script:Language = $Language

# Polish output needs a console that can render the diacritics. On Windows
# PowerShell 5.1 the output encoding defaults to the OEM code page, which turns
# them into mojibake even though the file itself is correct UTF-8. Setting the
# console to UTF-8 is a display-only change, local to this process.
if ($script:Language -ne 'en') {
    try {
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    } catch {
        Write-Verbose 'could not set the console output encoding to UTF-8'
    }
}

# --------------------------------------------------------------------------
# Reporting helpers
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Message catalogue
# --------------------------------------------------------------------------
#
# One entry per message, keyed by id, with an 'en' string and either a 'pl'
# string or an explicit EnglishOnly marker. There is deliberately no second
# copy of any text anywhere else in this file: every translatable line is
# emitted through T.
#
# Rules that keep it honest:
#
#   * A missing 'pl' falls back to the English string, visibly -- an English
#     line among Polish ones is the signal. Never a blank, never the key id.
#   * EnglishOnly marks a message that is meant to stay English, so the
#     self-test can tell "deliberate" from "forgotten".
#   * Technical identifiers are NOT translated: option names, registry paths,
#     command lines, CAPI:, and strings quoted verbatim from Windows, OpenSSH
#     or certutil. Those stay in the format arguments or in the English text,
#     so a command copied out of Polish output is the same command.
#   * Values are single-line, single-quoted strings. tests/test_windows_catalogue.py
#     parses this block to enforce the invariant, so keep the shape regular:
#     one key per line, then en/pl/EnglishOnly one per line.
#
# Run with -SelfTest to check the invariant from PowerShell itself.

$script:Messages = @{

    # ---- banner ----------------------------------------------------------
    'hdr.title' = @{
        en = 'Smart card SSH readiness check (PuTTY-CAC)'
        pl = 'Kontrola gotowości do logowania SSH kartą inteligentną (PuTTY-CAC)'
    }
    'hdr.platform' = @{
        en = 'PowerShell {0} on {1}'
        pl = 'PowerShell {0} w systemie {1}'
    }
    'hdr.readonly' = @{
        en = 'Read-only: nothing is launched, downloaded, installed or modified.'
        pl = 'Tylko odczyt: nic nie jest uruchamiane, pobierane, instalowane ani zmieniane.'
    }
    'hdr.launchmode' = @{
        en = '-Launch given: configuration found necessary WILL be applied, each change reported with its undo.'
        pl = 'Podano -Launch: potrzebne ustawienia ZOSTANA zastosowane, kazda zmiana z poleceniem cofajacym.'
    }
    'hdr.nokey' = @{
        en = 'No private key is read and no PIN is requested, stored or logged.'
        pl = 'Klucz prywatny nie jest odczytywany; PIN nie jest pobierany, zapisywany ani logowany.'
    }
    'hdr.noadmin1' = @{
        en = 'The checks need no administrator rights; only the suggested'
        pl = 'Kontrole nie wymagają uprawnień administratora; wymagają ich tylko'
    }
    'hdr.noadmin2' = @{
        en = 'remedies (installing a minidriver) do.'
        pl = 'proponowane naprawy (instalacja ministerownika).'
    }

    # ---- section titles --------------------------------------------------
    'sec.dependencies' = @{
        en = 'Dependencies'
        pl = 'Zależności'
    }
    'sec.tokens' = @{
        en = 'Tokens'
        pl = 'Tokeny'
    }
    'sec.certificates' = @{
        en = 'Card certificates and key containers'
        pl = 'Certyfikaty na karcie i kontenery kluczy'
    }
    'sec.result' = @{
        en = 'Result'
        pl = 'Wynik'
    }
    'sec.commands' = @{
        en = 'Commands to run on this workstation'
        pl = 'Polecenia do uruchomienia na tej stacji roboczej'
    }
    'sec.applying' = @{
        en = 'Applying (-Launch)'
        pl = 'Stosowanie zmian (-Launch)'
    }

    # ---- checks: PuTTY-CAC ----------------------------------------------
    'chk.putty' = @{
        en = 'PuTTY-CAC present'
        pl = 'PuTTY-CAC jest zainstalowany'
    }
    'chk.putty.absent' = @{
        en = 'no putty.exe found in the usual install locations or on PATH'
        pl = 'nie znaleziono putty.exe w typowych lokalizacjach instalacji ani w PATH'
    }
    'chk.putty.stock' = @{
        en = 'this looks like stock PuTTY, which has no CAPI: support -- {0}'
        pl = 'to wygląda na zwykle PuTTY, które nie obsługuje CAPI: -- {0}'
    }
    'chk.putty.remedy' = @{
        en = 'install PuTTY-CAC (releases: https://github.com/NoMoreFood/putty-cac/releases)'
        pl = 'zainstaluj PuTTY-CAC (wydania: https://github.com/NoMoreFood/putty-cac/releases)'
    }
    'chk.putty.remedy.path' = @{
        en = 'install PuTTY-CAC, or pass -PuttyPath to point at an existing PuTTY-CAC install'
        pl = 'zainstaluj PuTTY-CAC albo wskaż istniejącą instalację przez -PuttyPath'
    }
    'fix.putty.install' = @{
        en = 'Install PuTTY-CAC (stock PuTTY cannot do CAPI: at all)'
        pl = 'Zainstaluj PuTTY-CAC (zwykle PuTTY w ogóle nie obsługuje CAPI:)'
    }
    'fix.putty.install.stock' = @{
        en = 'Install PuTTY-CAC (what is installed is stock PuTTY, which has no CAPI: support)'
        pl = 'Zainstaluj PuTTY-CAC (zainstalowane jest zwykle PuTTY, bez obsługi CAPI:)'
    }
    'putty.detectedvia' = @{
        en = 'detected via: {0}'
        pl = 'rozpoznano przez: {0}'
    }
    'putty.probe' = @{
        en = 'plink -x509off probe: {0}'
        pl = 'test plink -x509off: {0}'
    }

    # ---- checks: OpenSC --------------------------------------------------
    'chk.opensc' = @{
        en = 'OpenSC present (optional)'
        pl = 'OpenSC jest zainstalowany (opcjonalnie)'
    }
    'chk.opensc.found' = @{
        en = 'pkcs11-tool.exe and opensc-tool.exe found under {0}'
        pl = 'znaleziono pkcs11-tool.exe i opensc-tool.exe w {0}'
    }
    'chk.opensc.partial' = @{
        en = 'only part of the OpenSC toolset was found'
        pl = 'znaleziono tylko część narzędzi OpenSC'
    }
    'chk.opensc.absent' = @{
        en = 'pkcs11-tool.exe / opensc-tool.exe not found'
        pl = 'nie znaleziono pkcs11-tool.exe ani opensc-tool.exe'
    }
    'chk.opensc.remedy' = @{
        en = 'only needed to read the thumbprint straight off the card; certutil can usually do it alone'
        pl = 'potrzebne tylko do odczytu odcisku bezpośrednio z karty; zwykle wystarcza samo certutil'
    }
    'fix.opensc.install' = @{
        en = 'Install OpenSC, to read the certificate off the card'
        pl = 'Zainstaluj OpenSC, aby odczytać certyfikat z karty'
    }

    # ---- checks: Pageant -------------------------------------------------
    'chk.pageant' = @{
        en = 'Pageant is running and serving'
        pl = 'Pageant działa i obsługuje żądania'
    }
    'chk.pageant.detail' = @{
        en = '{0}  [{1}]'
        pl = '{0}  [{1}]'
    }
    'chk.pageant.remedy' = @{
        en = 'start Pageant and load the card certificate into it before connecting: "{0}"'
        pl = 'uruchom Pageant i wczytaj do niego certyfikat karty przed połączeniem: "{0}"'
    }
    'pageant.process' = @{
        en = 'process: {0}'
        pl = 'proces: {0}'
    }
    'pageant.attime1' = @{
        en = 'Pageant must already be running with the certificate loaded'
        pl = 'Pageant musi już działać z wczytanym certyfikatem'
    }
    'pageant.attime2' = @{
        en = 'AT CONNECT TIME. Adding it to Pageant after the session is up'
        pl = 'W MOMENCIE POŁĄCZENIA. Dodanie go do Pageanta po zestawieniu sesji'
    }
    'pageant.attime3' = @{
        en = 'does not retrofit agent forwarding onto that session.'
        pl = 'nie włączy przekazywania agenta w tej sesji.'
    }
    'fix.pageant.start' = @{
        en = 'Start Pageant with the card certificate loaded'
        pl = 'Uruchom Pageant z wczytanym certyfikatem karty'
    }

    # ---- checks: session agent forwarding --------------------------------
    'chk.session' = @{
        en = 'Saved session: agent forwarding'
        pl = 'Zapisana sesja: przekazywanie agenta'
    }
    'chk.session.nonamegiven' = @{
        en = 'no -SessionName given, so the per-session AgentFwd/TryAgent values cannot be read'
        pl = 'nie podano -SessionName, więc nie można odczytać wartości AgentFwd/TryAgent dla sesji'
    }
    'chk.session.nonamegiven.remedy' = @{
        en = 'pass -SessionName <saved session> to have them checked, or tick Connection > SSH > Auth > "Allow agent forwarding" in the PuTTY UI'
        pl = 'podaj -SessionName <zapisana sesja>, aby je sprawdzic, albo zaznacz Connection > SSH > Auth > "Allow agent forwarding" w oknie PuTTY'
    }
    'chk.session.notfound' = @{
        en = 'no saved session named "{0}"; saved sessions are: {1}'
        pl = 'brak zapisanej sesji o nazwie "{0}"; zapisane sesję to: {1}'
    }
    'chk.session.notfound.remedy' = @{
        en = 'save the session in PuTTY first, or pass -SessionName exactly as PuTTY lists it'
        pl = 'najpierw zapisz sesję w PuTTY albo podaj -SessionName dokładnie tak, jak wyświetla ją PuTTY'
    }
    'chk.session.ok' = @{
        en = 'session "{0}": AgentFwd={1}, TryAgent={2}'
        pl = 'sesja "{0}": AgentFwd={1}, TryAgent={2}'
    }
    'chk.session.bad' = @{
        en = 'session "{0}": {1}'
        pl = 'sesja "{0}": {1}'
    }
    'chk.session.bad.fwd' = @{
        en = 'AgentFwd={0} (agent forwarding off)'
        pl = 'AgentFwd={0} (przekazywanie agenta wyłączone)'
    }
    'chk.session.bad.try' = @{
        en = 'TryAgent={0} (Pageant not consulted at all)'
        pl = 'TryAgent={0} (Pageant w ogóle nie jest uzywany)'
    }
    'chk.session.bad.remedy' = @{
        en = 'either tick Connection > SSH > Auth > "Allow agent forwarding" and re-save the session, or set the values directly (commands below)'
        pl = 'zaznacz Connection > SSH > Auth > "Allow agent forwarding" i zapisz sesję ponownie albo ustaw wartości bezpośrednio (polecenia niżej)'
    }
    'fix.session.agentfwd' = @{
        en = 'Enable agent forwarding on the saved session "{0}"'
        pl = 'Włącz przekazywanie agenta w zapisanej sesji "{0}"'
    }
    'session.nothingunless' = @{
        en = '(the script changes nothing unless -Launch is given)'
        pl = '(skrypt niczego nie zmienia, o ile nie podano -Launch)'
    }
    'session.anote1' = @{
        en = 'Note: -A on the command line covers this run regardless of AgentFwd;'
        pl = 'Uwaga: -A w wierszu poleceń działa w tym uruchomieniu niezależnie od AgentFwd;'
    }
    'session.anote2' = @{
        en = 'the saved value matters when the session is launched from the UI.'
        pl = 'zapisana wartosc ma znaczenie przy uruchamianiu sesji z okna PuTTY.'
    }
    'session.narrowed' = @{
        en = 'Narrowed to one token by -Reader "{0}".'
        pl = 'Zawężono do jednego tokena przez -Reader "{0}".'
    }

    # ---- checks: X.509 and Pageant preload -------------------------------
    'x509.unset' = @{
        en = 'global AuthX509: not set (PuTTY-CAC default)'
        pl = 'globalne AuthX509: nieustawione (domyslnie w PuTTY-CAC)'
    }
    'x509.off' = @{
        en = 'global AuthX509 = 0 (X.509 mode off, which is what you want)'
        pl = 'globalne AuthX509 = 0 (tryb X.509 wyłączony, i o to chodzi)'
    }
    'x509.on' = @{
        en = 'global AuthX509 = {0} (X.509 mode ON globally -- -x509off overrides it per run)'
        pl = 'globalne AuthX509 = {0} (tryb X.509 WŁĄCZONY globalnie -- -x509off wyłącza go na jedno uruchomienie)'
    }
    'chk.preload' = @{
        en = 'Pageant certificate preload'
        pl = 'Wczytywanie certyfikatu przez Pageanta'
    }
    'chk.preload.unknown' = @{
        en = 'Pageant preload configuration: unknown (PuTTY registry key unreadable)'
        pl = 'Konfiguracja wczytywania w Pageancie: nieznana (nie można odczytać klucza rejestru PuTTY)'
    }
    'chk.preload.autoload' = @{
        en = 'AutoloadCerts = 1: Pageant re-enumerates the ENTIRE Windows certificate store at every start and rewrites SaveCertList (currently {0}), dead key containers included'
        pl = 'AutoloadCerts = 1: Pageant przy każdym starcie przegląda CAŁY magazyn certyfikatów Windows i nadpisuje SaveCertList (obecnie {0}), razem z martwymi kontenerami kluczy'
    }
    'chk.preload.autoload.remedy' = @{
        en = 'set AutoloadCerts = 0 and preload the one certificate instead. Trimming SaveCertList by hand does nothing while this is 1 -- it is rebuilt on the next start'
        pl = 'ustaw AutoloadCerts = 0 i wczytuj tylko jeden certyfikat. Ręczne skracanie SaveCertList nic nie daje, dopóki jest 1 -- lista jest odbudowywana przy kolejnym starcie'
    }
    'chk.preload.ok' = @{
        en = 'AutoloadCerts = 0, SaveCertList holds {0}'
        pl = 'AutoloadCerts = 0, SaveCertList zawiera {0}'
    }
    'chk.preload.default' = @{
        en = 'Pageant preload: AutoloadCerts not set (default), SaveCertList holds {0}'
        pl = 'Wczytywanie w Pageancie: AutoloadCerts nieustawione (domyslnie), SaveCertList zawiera {0}'
    }
    'preload.entries' = @{
        en = '{0} entr(y/ies)'
        pl = 'wpisów: {0}'
    }
    'preload.notset' = @{
        en = 'not set'
        pl = 'nieustawione'
    }
    'preload.maxauth1' = @{
        en = 'Why it matters: the agent offers keys ONE AT A TIME and OpenSSH''s'
        pl = 'Dlaczego to ważne: agent podaje klucze PO JEDNYM, a domyslne'
    }
    'preload.maxauth2' = @{
        en = 'default MaxAuthTries is 6. With a full store the card''s key may'
        pl = 'MaxAuthTries w OpenSSH wynosi 6. Przy pełnym magazynie klucz karty'
    }
    'preload.maxauth3' = @{
        en = 'never be reached, and you get "Server refused our key" -- the same'
        pl = 'może nigdy nie zostać użyty, a komunikat brzmi "Server refused our key"'
    }
    'preload.maxauth4' = @{
        en = 'message as the X.509 trap and as a stale store entry.'
        pl = '-- tak samo jak przy pułapce X.509 i przy nieaktualnym wpisie magazynu.'
    }
    'preload.trim1' = @{
        en = 'Note: {0} entries are saved. The store is no longer being'
        pl = 'Uwaga: zapisanych wpisów: {0}. Magazyn nie jest już przeglądany,'
    }
    'preload.trim2' = @{
        en = 'enumerated, so trimming the list will now stick -- and with'
        pl = 'więc skrócenie listy tym razem się utrzyma -- a przy'
    }
    'preload.trim3' = @{
        en = 'MaxAuthTries at 6 it is worth trimming.'
        pl = 'MaxAuthTries równym 6 warto ją skrócić.'
    }
    'fix.preload.autoload' = @{
        en = 'Stop Pageant enumerating the whole certificate store (MaxAuthTries)'
        pl = 'Przestań przeglądać cały magazyn certyfikatów w Pageancie (MaxAuthTries)'
    }
    'fix.startup.shortcut' = @{
        en = 'Load the certificate into Pageant at every logon'
        pl = 'Wczytuj certyfikat do Pageanta przy każdym logowaniu'
    }
    'fix.startup.shortcut.note' = @{
        en = 'One line, so it pastes as a single unit. Replaces any existing Pageant shortcut in Startup; -Launch keeps a .bak of the old one.'
        pl = 'Jedna linia, więc wkleja się w całości. Zastępuje istniejący skrot Pageanta w Autostarcie; -Launch zachowuje kopie .bak poprzedniego.'
    }

    # ---- checks: reader and card -----------------------------------------
    'chk.reader' = @{
        en = 'Reader and card present'
        pl = 'Czytnik i karta są obecne'
    }
    'chk.reader.nooutput' = @{
        en = 'certutil -scinfo produced no output'
        pl = 'certutil -scinfo nie zwrocil żadnych danych'
    }
    'chk.reader.nooutput.remedy' = @{
        en = 'check that the Smart Card service (SCardSvr) is running and a reader is attached'
        pl = 'sprawdź, czy usługa kart inteligentnych (SCardSvr) działa i czy czytnik jest podłączony'
    }
    'chk.reader.noreaders' = @{
        en = 'no smart card readers reported'
        pl = 'nie zgłoszono żadnego czytnika kart inteligentnych'
    }
    'chk.reader.noreaders.remedy' = @{
        en = 'attach a reader or token, then re-run'
        pl = 'podlacz czytnik lub token i uruchom ponownie'
    }
    'chk.reader.nocard' = @{
        en = '{0} reader(s) present but none holds a card'
        pl = 'czytników: {0}, ale w zadnym nie ma karty'
    }
    'chk.reader.nocard.remedy' = @{
        en = 'insert the token or card, then re-run'
        pl = 'włóż token lub kartę i uruchom ponownie'
    }
    'chk.reader.ok' = @{
        en = '{0} of {1} reader(s) hold a card: {2}'
        pl = 'kartę zawiera {0} z {1} czytników: {2}'
    }
    'reader.list' = @{
        en = 'readers: {0}'
        pl = 'czytniki: {0}'
    }
    'reader.empty' = @{
        en = 'empty: {0}'
        pl = 'puste: {0}'
    }
    'tokens.minidriver.unknown' = @{
        en = 'Bound minidriver: unknown (Get-PnpDevice unavailable on this host)'
        pl = 'Powiązany ministerownik: nieznany (Get-PnpDevice niedostępne na tym hoście)'
    }
    'tokens.minidriver.none' = @{
        en = 'Bound minidriver: none reported for a present card'
        pl = 'Powiązany ministerownik: brak zgłoszonego dla obecnej karty'
    }
    'tokens.none' = @{
        en = 'No tokens to classify.'
        pl = 'Brak tokenów do sklasyfikowania.'
    }
    'tokens.multiple1' = @{
        en = '{0} tokens are attached at once. The script will not pick one for you.'
        pl = 'Podłączono jednoczesnie tokenów: {0}. Skrypt nie wybierze za Ciebie.'
    }
    'tokens.multiple2' = @{
        en = 'Narrow the choice with -Reader <text> or -Thumbprint <sha1> if the'
        pl = 'Zawęź wybór przez -Reader <tekst> lub -Thumbprint <sha1>, jeśli poniższe'
    }
    'tokens.multiple3' = @{
        en = 'checks below leave more than one usable certificate.'
        pl = 'kontrole zostawia więcej niż jeden użyteczny certyfikat.'
    }
    'tokens.readernotmatched' = @{
        en = 'No reader name contains "{0}"; showing all readers.'
        pl = 'Żadna nazwa czytnika nie zawiera "{0}"; pokazano wszystkie czytniki.'
    }
    'token.generic' = @{
        en = 'PIV token (vendor not recognised)'
        pl = 'Token PIV (nierozpoznany producent)'
    }
    'minidriver.inbox' = @{
        en = 'Windows inbox PIV minidriver (msclmd.inf)'
        pl = 'wbudowany ministerownik PIV systemu Windows (msclmd.inf)'
    }
    'minidriver.none' = @{
        en = 'no minidriver bound (scunknown.inf)'
        pl = 'brak powiazanego ministerownika (scunknown.inf)'
    }
    'minidriver.vendor' = @{
        en = 'vendor minidriver ({0})'
        pl = 'ministerownik producenta ({0})'
    }
    'minidriver.other' = @{
        en = 'minidriver {0}'
        pl = 'ministerownik {0}'
    }
    'minidriver.unknown' = @{
        en = 'unknown'
        pl = 'nieznany'
    }

    # ---- certificates ----------------------------------------------------
    'cert.heading' = @{
        en = 'Certificate {0}'
        pl = 'Certyfikat {0}'
    }
    'cert.reader' = @{
        en = 'reader:         {0}'
        pl = 'czytnik:        {0}'
    }
    'cert.source' = @{
        en = 'read from:      {0}'
        pl = 'odczytano z:    {0}'
    }
    'cert.containercard' = @{
        en = 'container on card:  {0}'
        pl = 'kontener na karcie: {0}'
    }
    'cert.containercard.unknown' = @{
        en = 'container on card:  unknown'
        pl = 'kontener na karcie: nieznany'
    }
    'cert.containerstore' = @{
        en = 'container in store: {0}'
        pl = 'kontener w magazynie: {0}'
    }
    'cert.containerstore.unknown' = @{
        en = 'container in store: unknown'
        pl = 'kontener w magazynie: nieznany'
    }
    'cert.filtered' = @{
        en = 'Filtered to readers matching "{0}": {1} candidate(s)'
        pl = 'Zawężono do czytników pasujących do "{0}": kandydatów: {1}'
    }
    'chk.cert.none' = @{
        en = 'A usable card certificate was found'
        pl = 'Znaleziono użyteczny certyfikat na karcie'
    }
    'chk.cert.none.detail' = @{
        en = 'no certificate could be read from any card'
        pl = 'nie udało się odczytać certyfikatu z żadnej karty'
    }
    'chk.cert.none.remedy' = @{
        en = 'the card may not be provisioned, or its minidriver may be missing -- see below'
        pl = 'karta może nie być zainicjowana albo brakuje jej ministerownika -- patrz niżej'
    }
    'chk.cert.instore' = @{
        en = '{0}: present in the user certificate store'
        pl = '{0}: obecny w magazynie certyfikatów użytkownika'
    }
    'chk.cert.instore.detail' = @{
        en = 'the certificate is on the card but not in Cert:\CurrentUser\My'
        pl = 'certyfikat jest na karcie, ale nie ma go w Cert:\CurrentUser\My'
    }
    'chk.cert.instore.remedy' = @{
        en = 'CAPI: addressing reads the store, so the certificate has to be registered there'
        pl = 'adresowanie CAPI: czyta magazyn, więc certyfikat musi być tam zarejestrowany'
    }
    'fix.cert.reinsert' = @{
        en = 'Re-insert the token, then re-run -- certificate {0} is on the card but not in the store'
        pl = 'Wyjmij i włóż token ponownie, potem uruchom skrypt jeszcze raz -- certyfikat {0} jest na karcie, ale nie w magazynie'
    }
    'fix.cert.reinsert.note' = @{
        en = 'The propagation service only registers card certificates on an insertion event, so a certificate written to a card that was already in the reader is never seen. Unplug the token, plug it back in, and run this script again. The two steps that follow are only needed if that does not fix it.'
        pl = 'Usługa propagacji rejestruje certyfikaty karty tylko przy zdarzeniu włożenia, więc certyfikat zapisany na karcie już obecnej w czytniku nigdy nie zostanie zauważony. Wyjmij token, włóż go ponownie i uruchom skrypt jeszcze raz. Dwa kolejne kroki są potrzebne tylko wtedy, gdy to nie pomoże.'
    }
    'fix.cert.addstore' = @{
        en = 'Only if re-inserting did not work: add certificate {0} to the store'
        pl = 'Tylko jeśli ponowne wlozenie nie pomogło: dodaj certyfikat {0} do magazynu'
    }
    'fix.cert.addstore.note' = @{
        en = 'Read the certificate off the card first -- see -UseOpenSC, which prints the pkcs11-tool command that writes it to a .der file.'
        pl = 'Najpierw odczytaj certyfikat z karty -- zobacz -UseOpenSC, które wypisuje polecenie pkcs11-tool zapisujące go do pliku .der.'
    }
    'fix.cert.repair' = @{
        en = 'Only if re-inserting did not work: bind {0} to the key on the card'
        pl = 'Tylko jeśli ponowne wlozenie nie pomogło: powiąż {0} z kluczem na karcie'
    }
    'fix.cert.repair.note' = @{
        en = '"Encryption test passed" in the output means the binding took. The CSP below is the one -scinfo reported for this card; a wrong CSP fails in a way that looks like a bad card.'
        pl = 'Napis "Encryption test passed" w wyniku oznacza, że powiązanie się udało. Poniższy CSP to ten, który -scinfo zgłosił dla tej karty; błędny CSP kończy się błędem wyglądającym jak uszkodzona karta.'
    }
    'chk.cert.keyset' = @{
        en = '{0}: key container resolves'
        pl = '{0}: kontener klucza daje się otworzyć'
    }
    'chk.cert.keyset.detail' = @{
        en = 'certutil reports "Missing stored keyset" -- the store entry names a key container that cannot be opened'
        pl = 'certutil zgłasza "Missing stored keyset" -- wpis magazynu wskazuje kontener klucza, którego nie można otworzyć'
    }
    'chk.cert.keyset.remedy' = @{
        en = 'this certificate is unusable; pick another, or delete the stale store entry and re-register the card certificate'
        pl = 'ten certyfikat jest bezużyteczny; wybierz inny albo usuń nieaktualny wpis i zarejestruj certyfikat karty ponownie'
    }
    'fix.cert.rebind' = @{
        en = 'Re-bind store entry {0} to the key on the card'
        pl = 'Powiąż ponownie wpis magazynu {0} z kluczem na karcie'
    }
    'fix.cert.rebind.note' = @{
        en = '"Encryption test passed" in the output means the binding took. If it still fails the certificate belongs to a card that is not here -- pick another, or delete the entry with "certutil -user -delstore My <thumbprint>".'
        pl = 'Napis "Encryption test passed" w wyniku oznacza, że powiązanie się udało. Jeśli nadal się nie udaje, certyfikat należy do karty, ktorej tu nie ma -- wybierz inny albo usuń wpis poleceniem "certutil -user -delstore My <thumbprint>".'
    }
    'chk.cert.container' = @{
        en = '{0}: key container matches the card'
        pl = '{0}: kontener klucza zgadza się z kartą'
    }
    'chk.cert.container.unknown' = @{
        en = 'could not read one or both container names, so the comparison is unknown'
        pl = 'nie udało się odczytać jednej lub obu nazw kontenerow, więc porównanie jest nieznane'
    }
    'chk.cert.container.unknown.remedy' = @{
        en = 'run "certutil -scinfo -silent" and "certutil -silent -user -store My <thumbprint>" by hand and compare the Key Container lines'
        pl = 'uruchom ręcznie "certutil -scinfo -silent" oraz "certutil -silent -user -store My <thumbprint>" i porównaj linie Key Container'
    }
    'chk.cert.container.ok' = @{
        en = 'store and card both name {0}'
        pl = 'magazyn i karta wskazują ten sam: {0}'
    }
    'chk.cert.container.bad' = @{
        en = 'store names {0}, but the card holds {1}'
        pl = 'magazyn wskazuje {0}, a karta zawiera {1}'
    }
    'chk.cert.container.bad.remedy' = @{
        en = 'this store entry belongs to a different (probably older) card; Windows will say the smart card cannot perform the requested operation. Delete the stale entry or pick the certificate whose container is on this card'
        pl = 'ten wpis magazynu należy do innej (zapewne starszej) karty; Windows powie, że karta nie może wykonać żądanej operacji. Usuń nieaktualny wpis albo wybierz certyfikat, którego kontener jest na tej karcie'
    }
    'store.count1' = @{
        en = 'The user certificate store holds {0} entr(y/ies).'
        pl = 'Magazyn certyfikatów użytkownika zawiera wpisów: {0}.'
    }
    'store.count2' = @{
        en = 'Stale smart card entries are normal and harmless until one is picked'
        pl = 'Nieaktualne wpisy kart są normalne i nieszkodliwe, dopóki któregoś'
    }
    'store.count3' = @{
        en = 'by mistake; always take the thumbprint from the card, as above.'
        pl = 'nie wybierze się przez pomyłkę; odcisk zawsze bierz z karty, jak wyżej.'
    }
    'opensc.agrees' = @{
        en = 'OpenSC agrees with certutil on {0} ({1})'
        pl = 'OpenSC zgadza się z certutil co do {0} ({1})'
    }
    'opensc.extra' = @{
        en = 'OpenSC found a certificate certutil did not report: {0} ({1})'
        pl = 'OpenSC znalazł certyfikat, którego certutil nie zgłosił: {0} ({1})'
    }

    # ---- result ----------------------------------------------------------
    'result.nocert' = @{
        en = 'No usable card certificate, so no command is emitted.'
        pl = 'Brak uzytecznego certyfikatu na karcie, więc nie wypisano polecenia.'
    }
    'result.pertoken' = @{
        en = 'More than one token is attached, so the advice below is given per token.'
        pl = 'Podłączono więcej niż jeden token, więc poniższe wskazówki podano dla każdego osobno.'
    }
    'result.readoff1' = @{
        en = 'To read the certificates straight off the card, independently of the'
        pl = 'Aby odczytać certyfikaty bezpośrednio z karty, niezależnie od'
    }
    'result.readoff2' = @{
        en = 'Windows store, re-run this script with -UseOpenSC, or by hand:'
        pl = 'magazynu Windows, uruchom skrypt z -UseOpenSC albo ręcznie:'
    }
    'result.ambiguous1' = @{
        en = '{0} usable certificates were found. Choose one -- the script will not'
        pl = 'Znaleziono użytecznych certyfikatów: {0}. Wybierz jeden -- skrypt nie'
    }
    'result.ambiguous2' = @{
        en = 'choose for you:'
        pl = 'wybierze za Ciebie:'
    }
    'result.ambiguous3' = @{
        en = 'Re-run with -Thumbprint <sha1>, or -Reader <text> to narrow by reader.'
        pl = 'Uruchom ponownie z -Thumbprint <sha1> albo -Reader <tekst>, aby zawezic po czytniku.'
    }
    'result.ambiguous.reader' = @{
        en = '-Thumbprint {0}    (reader: {1})'
        pl = '-Thumbprint {0}    (czytnik: {1})'
    }
    'fix.rerun' = @{
        en = 'Re-run this script once the steps above are done'
        pl = 'Uruchom ten skrypt ponownie po wykonaniu powyższych kroków'
    }
    'fix.rerun.named' = @{
        en = 'Re-run naming the certificate you want'
        pl = 'Uruchom ponownie, wskazując wybrany certyfikat'
    }
    'fix.rerun.named.note' = @{
        en = 'The thumbprint above is the first of the usable certificates listed; substitute whichever one you mean.'
        pl = 'Powyższy odcisk to pierwszy z wypisanych użytecznych certyfikatów; podstaw ten, o który Ci chodzi.'
    }
    'result.allpass' = @{
        en = 'All checks passed. Run this yourself -- the script does not launch it.'
        pl = 'Wszystkie kontrole zaliczone. Uruchom to samodzielnie -- skrypt tego nie robi.'
    }
    'result.allpass.launch' = @{
        en = 'All checks passed. -Launch will apply what is needed and then connect.'
        pl = 'Wszystkie kontrole zaliczone. -Launch zastosuje potrzebne zmiany i polaczy się.'
    }
    'result.interactive' = @{
        en = 'Interactive (PuTTY window):'
        pl = 'Interaktywnie (okno PuTTY):'
    }
    'result.scripted' = @{
        en = 'Scripted / batch (plink, no interactive prompts):'
        pl = 'Skryptowo / wsadowo (plink, bez pytań interaktywnych):'
    }
    'result.placeholder1' = @{
        en = 'NOTE: -User and/or -ComputerName were not given, so the command above'
        pl = 'UWAGA: nie podano -User i/lub -ComputerName, więc powyższe polecenie'
    }
    'result.placeholder2' = @{
        en = 'contains example values. Re-run with your own, e.g.'
        pl = 'zawiera wartości przykładowe. Uruchom ponownie z własnymi, np.'
    }

    # ---- command block ---------------------------------------------------
    'block.nothingtofix' = @{
        en = 'Every check passed: there is nothing to fix on this workstation.'
        pl = 'Wszystkie kontrole zaliczone: na tej stacji nie ma nic do poprawienia.'
    }
    'block.copyrun' = @{
        en = 'Nothing below has been applied. Copy and run these yourself, in order.'
        pl = 'Nic poniższego nie zostało zastosowane. Skopiuj i uruchom samodzielnie, po kolei.'
    }
    'block.unit' = @{
        en = '(these lines are one unit -- paste them in together)'
        pl = '(te linie stanowią calosc -- wklej je razem)'
    }
    'block.separate' = @{
        en = '(separate commands; run them in this order)'
        pl = '(osobne polecenia; uruchom je w tej kolejności)'
    }
    'block.connect' = @{
        en = 'Connect'
        pl = 'Połącz się'
    }

    # ---- -Launch ---------------------------------------------------------
    'launch.stopinstall' = @{
        en = 'Stopping before any change: something has to be installed first.'
        pl = 'Zatrzymano przed jakąkolwiek zmianą: najpierw trzeba cos zainstalować.'
    }
    'launch.noinstall1' = @{
        en = '-Launch configures what is already on this machine; it does not install'
        pl = '-Launch konfiguruje to, co już jest na tej maszynie; nie instaluje'
    }
    'launch.noinstall2' = @{
        en = 'software, because that downloads, usually needs elevation, and changes'
        pl = 'oprogramowania, bo to pobieranie, zwykle z podniesieniem uprawnień, i zmienia'
    }
    'launch.noinstall3' = @{
        en = 'the machine rather than your configuration.'
        pl = 'maszynę, a nie Twoją konfigurację.'
    }
    'launch.installthenrerun' = @{
        en = 'Install the above, then re-run. NOTHING HAS BEEN CHANGED.'
        pl = 'Zainstaluj powyższe i uruchom ponownie. NICZEGO NIE ZMIENIONO.'
    }
    'launch.nothingtoapply' = @{
        en = 'Nothing to apply: this workstation is already configured.'
        pl = 'Nie ma czego stosowac: ta stacja jest już skonfigurowana.'
    }
    'launch.skip' = @{
        en = '[SKIP] {0}'
        pl = '[POMIŃ] {0}'
    }
    'launch.skip.why1' = @{
        en = 'Cannot be applied automatically -- it needs a decision or a'
        pl = 'Nie można zastosować automatycznie -- wymaga decyzji albo pliku,'
    }
    'launch.skip.why2' = @{
        en = 'file this script will not invent. Run it yourself:'
        pl = 'którego skrypt nie wymyśli. Uruchom to samodzielnie:'
    }
    'launch.done' = @{
        en = '[DONE] {0}'
        pl = '[ZROBIONE] {0}'
    }
    'launch.fail' = @{
        en = '[FAIL] {0}'
        pl = '[BŁĄD] {0}'
    }
    'launch.undo' = @{
        en = 'undo: {0}'
        pl = 'cofnięcie: {0}'
    }
    'launch.noresult' = @{
        en = 'no result returned'
        pl = 'nie zwrócono wyniku'
    }
    'launch.denied1' = @{
        en = 'If this says access is denied, it needs rights the checks do not'
        pl = 'Jeśli to błąd odmowy dostępu, potrzebne są uprawnienia, których kontrole'
    }
    'launch.denied2' = @{
        en = 'assume. Nothing is retried with elevation.'
        pl = 'nie zakładają. Nic nie jest ponawiane z podniesieniem uprawnień.'
    }
    'launch.failedcount' = @{
        en = '{0} step(s) did not complete, so no connection is started.'
        pl = 'Nieukończonych kroków: {0}, więc połączenie nie jest nawiązywane.'
    }
    'launch.fixthose' = @{
        en = 'Fix those and re-run, or run the printed commands yourself.'
        pl = 'Napraw je i uruchom ponownie albo wykonaj wypisane polecenia samodzielnie.'
    }
    'launch.rechecking' = @{
        en = 'Re-checking the applied state by reading it back...'
        pl = 'Ponowna kontrola zastosowanych zmian przez odczyt...'
    }
    'launch.recheckfailed' = @{
        en = 'The re-check did not pass, so no connection is started.'
        pl = 'Ponowna kontrola nie powiodła się, więc połączenie nie jest nawiązywane.'
    }
    'launch.recheckok' = @{
        en = 'Re-check passed.'
        pl = 'Ponowna kontrola zaliczona.'
    }
    'launch.nothingtostart' = @{
        en = 'PuTTY was not found, so there is nothing to start.'
        pl = 'Nie znaleziono PuTTY, więc nie ma czego uruchomić.'
    }
    'launch.starting' = @{
        en = 'Starting: {0}'
        pl = 'Uruchamianie: {0}'
    }
    'launch.pinprompt' = @{
        en = 'PuTTY will ask for the card PIN. This script never sees it.'
        pl = 'PuTTY zapyta o PIN karty. Ten skrypt nigdy go nie widzi.'
    }
    'launch.startfailed' = @{
        en = 'Could not start PuTTY: {0}'
        pl = 'Nie udało się uruchomić PuTTY: {0}'
    }
    'launch.nochanges' = @{
        en = 'No changes were made.'
        pl = 'Nie wprowadzono żadnych zmian.'
    }
    'launch.changecount' = @{
        en = '{0} change(s) made. To reverse them:'
        pl = 'Wprowadzonych zmian: {0}. Aby je cofnąć:'
    }
    'launch.needuserhost1' = @{
        en = '-Launch needs -User and -ComputerName: the command above still'
        pl = '-Launch wymaga -User i -ComputerName: powyższe polecenie nadal'
    }
    'launch.needuserhost2' = @{
        en = 'contains example values, and connecting to those would be pointless.'
        pl = 'zawiera wartości przykładowe, a łączenie się z nimi nie ma sensu.'
    }
    'launch.nothingchanged' = @{
        en = 'NOTHING HAS BEEN CHANGED.'
        pl = 'NICZEGO NIE ZMIENIONO.'
    }
    'recheck.x509ok' = @{
        en = 'AuthX509 = 0 or unset (X.509 mode off): ok'
        pl = 'AuthX509 = 0 lub nieustawione (tryb X.509 wyłączony): ok'
    }
    'recheck.x509bad' = @{
        en = 'AuthX509 = {0}: still on'
        pl = 'AuthX509 = {0}: nadal włączone'
    }
    'recheck.autoloadbad' = @{
        en = 'AutoloadCerts = 1: still enumerating the whole store'
        pl = 'AutoloadCerts = 1: nadal przegląda cały magazyn'
    }
    'recheck.autoloadok' = @{
        en = 'AutoloadCerts = 0 or unset: ok'
        pl = 'AutoloadCerts = 0 lub nieustawione: ok'
    }
    'recheck.sessionok' = @{
        en = 'session "{0}": AgentFwd=1, TryAgent=1: ok'
        pl = 'sesja "{0}": AgentFwd=1, TryAgent=1: ok'
    }
    'recheck.sessionbad' = @{
        en = 'session "{0}": AgentFwd={1}, TryAgent={2}: not both 1'
        pl = 'sesja "{0}": AgentFwd={1}, TryAgent={2}: nie obie rowne 1'
    }
    'recheck.shortcutok' = @{
        en = 'Startup shortcut arguments match the chosen certificate: ok'
        pl = 'Argumenty skrótu w Autostarcie zgadzają się z wybranym certyfikatem: ok'
    }
    'recheck.shortcutbad' = @{
        en = 'Startup shortcut arguments are "{0}": not the chosen certificate'
        pl = 'Argumenty skrótu w Autostarcie to "{0}": to nie wybrany certyfikat'
    }
    'recheck.shortcutunread' = @{
        en = 'Startup shortcut could not be read back'
        pl = 'Nie udało się odczytać skrótu w Autostarcie'
    }

    # ---- minidriver steps -------------------------------------------------
    'fix.minidriver.yubico' = @{
        en = 'Install the YubiKey Smart Card Minidriver (for provisioning/management)'
        pl = 'Zainstaluj YubiKey Smart Card Minidriver (do inicjowania i zarządzania)'
    }
    'fix.minidriver.hid' = @{
        en = 'Install the HID Crescendo Minidriver (no winget package exists)'
        pl = 'Zainstaluj HID Crescendo Minidriver (nie ma pakietu winget)'
    }
    'fix.minidriver.hid.note' = @{
        en = 'Download it from www.hidglobal.com/drivers -- HID''s own documentation names that as the location, and the portal refuses automated clients, so open it in a browser or ask your HID representative. Install docs: https://docs.hidglobal.com/crescendo-md-v1.3/MiniDriver/install_minidriver.htm'
        pl = 'Pobierz go z www.hidglobal.com/drivers -- własna dokumentacja HID wskazuje to miejsce, a portal odrzuca klientów automatycznych, więc otwórz go w przeglądarce lub zapytaj przedstawiciela HID. Dokumentacja instalacji: https://docs.hidglobal.com/crescendo-md-v1.3/MiniDriver/install_minidriver.htm'
    }
    'fix.minidriver.unknown' = @{
        en = 'Find the minidriver for this token: {0}'
        pl = 'Znajdź ministerownik dla tego tokena: {0}'
    }
    'fix.minidriver.unknown.note' = @{
        en = 'This vendor is not one the script recognises, so it cannot name the driver. Check the vendor''s own support site. Windows'' inbox PIV minidriver (msclmd.inf) is often enough on its own for an already-provisioned card, so this may not be the problem at all.'
        pl = 'Tego producenta skrypt nie rozpoznaje, więc nie wskaże sterownika. Sprawdź witrynę wsparcia producenta. Wbudowany ministerownik PIV systemu Windows (msclmd.inf) często w zupełności wystarcza dla karty już zainicjowanej, więc to może w ogóle nie być problem.'
    }

    # ---- PIN and touch policy ---------------------------------------------
    'pin.check' = @{
        en = 'Card PIN and touch policy for the chosen certificate'
        pl = 'Polityka PIN-u i dotknięcia karty dla wybranego certyfikatu'
    }
    'pin.slot' = @{
        en = 'slot {0}: PIN policy = {1}, touch policy = {2}'
        pl = 'slot {0}: polityka PIN-u = {1}, polityka dotknięcia = {2}'
    }
    'pin.unknown.vendor' = @{
        en = 'policy unknown: only a YubiKey can be read this way'
        pl = 'polityka nieznana: w ten sposób da się odczytać tylko YubiKey'
    }
    'pin.unknown.vendor.detail' = @{
        en = 'this token needs its vendor''s own management tooling; this script does not know a command for it and will not guess one'
        pl = 'ten token wymaga własnych narzędzi producenta; skrypt nie zna dla niego polecenia i nie będzie go zgadywał'
    }
    'pin.unknown.noykman' = @{
        en = 'policy unknown: ykman.exe was not found'
        pl = 'polityka nieznana: nie znaleziono ykman.exe'
    }
    'pin.unknown.noykman.detail' = @{
        en = 'install the YubiKey Manager CLI to have the policy reported: winget install --id Yubico.YubiKeyManagerCLI'
        pl = 'zainstaluj YubiKey Manager CLI, aby polityka była raportowana: winget install --id Yubico.YubiKeyManagerCLI'
    }
    'pin.unknown.noslot' = @{
        en = 'policy unknown: no PIV slot on this YubiKey holds the chosen certificate'
        pl = 'polityka nieznana: żaden slot PIV tego YubiKey nie zawiera wybranego certyfikatu'
    }
    'pin.unknown.noslot.detail' = @{
        en = 'the slot is matched by the certificate SHA-256, not assumed to be 9A, so no policy is reported rather than another slot''s'
        pl = 'slot jest dopasowywany po SHA-256 certyfikatu, a nie zakładany jako 9A, więc nie podajemy polityki innego slotu'
    }
    'pin.unknown.nocert' = @{
        en = 'policy unknown: the certificate bytes could not be read to match a slot'
        pl = 'polityka nieznana: nie udało się odczytać bajtów certyfikatu, by dopasować slot'
    }
    'pin.why.header' = @{
        en = 'Why sudo does not ask for the PIN again:'
        pl = 'Dlaczego sudo nie pyta ponownie o PIN:'
    }
    'pin.why1' = @{
        en = 'With PIN policy ONCE the card asks for the PIN once per session, so the'
        pl = 'Przy polityce PIN-u ONCE karta pyta o PIN raz na sesję, więc podpis, o który'
    }
    'pin.why2' = @{
        en = 'signature pam_ssh_agent_auth asks for during sudo needs no new PIN. That is'
        pl = 'pam_ssh_agent_auth prosi podczas sudo, nie wymaga nowego PIN-u. Tak została'
    }
    'pin.why3' = @{
        en = 'how the card was provisioned -- not a weakness in this configuration.'
        pl = 'zainicjowana karta -- to nie jest słabość tej konfiguracji.'
    }
    'pin.why4' = @{
        en = 'FIDO2 differs by protocol: it requires user presence for every assertion.'
        pl = 'FIDO2 różni się protokołem: wymaga obecności użytkownika przy każdej asercji.'
    }
    'pin.why5' = @{
        en = 'PIV does not, unless the slot was provisioned to.'
        pl = 'PIV tego nie wymaga, o ile slot nie został tak zainicjowany.'
    }
    'pin.why6' = @{
        en = 'To require a gesture per elevation the slot needs touch-policy ALWAYS, or'
        pl = 'Aby wymagać gestu przy każdym podniesieniu uprawnień, slot potrzebuje'
    }
    'pin.why7' = @{
        en = 'CACHED for a 15-second window. Both policies are fixed when the key is'
        pl = 'touch-policy ALWAYS albo CACHED (okno 15 sekund). Obie polityki ustala się'
    }
    'pin.why8' = @{
        en = 'generated or imported, so changing them means a new key and a re-issued'
        pl = 'przy generowaniu lub imporcie klucza, więc ich zmiana oznacza nowy klucz'
    }
    'pin.why9' = @{
        en = 'certificate.'
        pl = 'i ponownie wystawiony certyfikat.'
    }
    'pin.why10' = @{
        en = 'Separately, -forcepincache would remove the PIN prompt entirely -- see the'
        pl = 'Osobną sprawą jest -forcepincache, który usunąłby pytanie o PIN całkowicie'
    }
    'pin.why11' = @{
        en = 'note above. It is not recommended.'
        pl = '-- patrz uwaga wyżej. Nie jest zalecany.'
    }

    # ---- detection diagnostics -------------------------------------------
    # Deliberately English. These name binary symbols and exact option
    # spellings ("CAPI:", "-x509off", "plink.exe") and are what an operator
    # pastes into a bug report; translating the frame around identifiers that
    # must stay verbatim would make them harder to compare, not easier.
    'detect.capi' = @{
        en = 'CAPI: prefix present in the putty.exe image'
        EnglishOnly = $true
    }
    'detect.plink.accepted' = @{
        en = 'plink accepted -x509off'
        EnglishOnly = $true
    }
    'detect.plink.rejected' = @{
        en = 'plink rejected -x509off as an unknown option'
        EnglishOnly = $true
    }
    'detect.probe.accepted' = @{
        en = 'accepted (-x509off is a known option)'
        EnglishOnly = $true
    }
    'detect.probe.rejected' = @{
        en = 'rejected (-x509off unknown: stock PuTTY)'
        EnglishOnly = $true
    }
    'detect.probe.inconclusive' = @{
        en = 'inconclusive'
        EnglishOnly = $true
    }
    'detect.probe.norun' = @{
        en = 'could not run plink.exe'
        EnglishOnly = $true
    }

    # ---- self-test --------------------------------------------------------
    'selftest.header' = @{
        en = 'Message catalogue self-test'
        pl = 'Autotest katalogu komunikatów'
    }
    'selftest.ok' = @{
        en = 'Catalogue holds: every message has a Polish translation or an explicit EnglishOnly marker.'
        pl = 'Katalog jest spójny: każdy komunikat ma tłumaczenie polskie albo jawny znacznik EnglishOnly.'
    }
    'selftest.missing' = @{
        en = 'Missing Polish translation, and not marked EnglishOnly:'
        pl = 'Brak tłumaczenia polskiego i brak znacznika EnglishOnly:'
    }
}

# Messages that are deliberately English only, with the reason. Kept as a
# separate list rather than a flag inside each entry so that the reason is
# recorded somewhere a reader will find it, and so the self-test can report
# "deliberate" counts without trawling the catalogue.
$script:EnglishOnly = @{}

<#
    Look up a message.

    Falls back to English when the requested language has no translation --
    visibly, because the English text itself is the signal that a translation
    is missing. Never returns a blank line.

    A completely unknown id returns a loud marker rather than nothing: that is
    a bug in the caller, and the self-test exists to catch it before an
    operator does.
#>
function T {
    param(
        [Parameter(Mandatory = $true)] [string] $Id,
        # NB: deliberately not called $Args. That is an automatic variable in
        # PowerShell and shadowing it inside a function is a trap.
        [object[]] $Fmt = @()
    )

    $entry = $null
    if ($script:Messages.ContainsKey($Id)) { $entry = $script:Messages[$Id] }

    if (-not $entry) {
        return ('[[missing message: {0}]]' -f $Id)
    }

    $text = $null
    if ($script:Language -ne 'en' -and $entry.ContainsKey($script:Language)) {
        $text = [string] $entry[$script:Language]
    }
    if (-not $text) { $text = [string] $entry['en'] }
    if (-not $text) { return ('[[empty message: {0}]]' -f $Id) }

    if (@($Fmt).Count -gt 0) { return ($text -f $Fmt) }
    return $text
}

function Invoke-CatalogueSelfTest {
    Write-Host ''
    Write-Host (T 'selftest.header') -ForegroundColor White
    Write-Host ('-' * 40) -ForegroundColor DarkGray

    $total = 0
    $translated = 0
    $deliberate = 0
    $missing = @()

    foreach ($id in ($script:Messages.Keys | Sort-Object)) {
        $total++
        $entry = $script:Messages[$id]
        if ($entry.ContainsKey('pl') -and [string] $entry['pl']) {
            $translated++
        } elseif ($script:EnglishOnly.ContainsKey($id) -or $entry.ContainsKey('EnglishOnly')) {
            $deliberate++
        } else {
            $missing += $id
        }
    }

    Write-Host ('  messages:              {0}' -f $total) -ForegroundColor Gray
    Write-Host ('  translated (pl):       {0}' -f $translated) -ForegroundColor Gray
    Write-Host ('  English only (marked): {0}' -f $deliberate) -ForegroundColor Gray
    Write-Host ('  missing:               {0}' -f @($missing).Count) -ForegroundColor Gray
    Write-Host ''

    if (@($missing).Count -gt 0) {
        Write-Host (T 'selftest.missing') -ForegroundColor Red
        foreach ($m in $missing) { Write-Host ('    {0}' -f $m) -ForegroundColor Red }
        Write-Host ''
        return 1
    }

    Write-Host (T 'selftest.ok') -ForegroundColor Green
    Write-Host ''
    return 0
}

$script:Findings = @()

# The ordered to-do list that the final "Commands to run on this workstation"
# block is built from. Steps are appended by the checks themselves, via
# Write-Finding -Fix, so there is exactly one copy of each remedy: the inline
# one and the summarised one are the same strings. Adding a remedy in one place
# and forgetting the other is then impossible by construction.
$script:Steps = @()
$script:StepSeq = 0

# Captured here, at script scope, while $PSBoundParameters still refers to the
# script's own arguments. Get-SelfInvocation rebuilds the command line from it.
$script:InvokedWith = $PSBoundParameters
$script:SelfPath = $PSCommandPath

# State shared with the -Launch apply blocks and the re-check. Initialised here
# because Set-StrictMode makes reading an undefined variable an error, and the
# re-check runs whether or not every one of these was set along the way.
$script:ChosenThumbprint = $null
$script:LaunchPageantExe = $null
$script:LaunchUser       = $null
$script:LaunchHost       = $null
$script:LaunchPort       = 22
$script:LaunchSessionKey = $null
$script:LaunchNeedAgentFwd = $false
$script:LaunchNeedTryAgent = $false
$script:StartupLnk       = $null
$script:StartupArgs      = $null

# Dependency ordering. The checks do not run in the order the operator must act
# in -- the certificate-store check happens last but has to be fixed early -- so
# each step carries an explicit rank and the block is sorted by it.
$script:OrderInstall  = 10   # get the software on the box
$script:OrderRegister = 20   # get the card's certificate into the Windows store
$script:OrderSettings = 30   # PuTTY / session settings
$script:OrderPreload  = 40   # Pageant's certificate list
$script:OrderAgent    = 50   # start Pageant with the certificate loaded
$script:OrderConnect  = 90   # connect

function Add-Step {
    param(
        [int] $Order,
        [string] $Label,
        [string[]] $Commands = @(),
        [string] $Note,
        # -Launch executes this instead of parsing the command strings. Keeping
        # the action beside the command that documents it is what stops the two
        # drifting; a step with no Apply is one -Launch cannot perform, and it
        # says so rather than pretending.
        [scriptblock] $Apply,
        [string[]] $Undo = @(),
        # Installs are deliberately excluded from -Launch. Flagged here rather
        # than inferred from the order, so the refusal is explicit.
        [switch] $IsInstall,
        # The commands of this step are one unit that must be pasted together
        # (they share state, e.g. a variable). Without this, multiple commands
        # are rendered as separately runnable lines. Every step has to survive
        # being pasted on its own into a fresh prompt.
        [switch] $Unit
    )
    $script:StepSeq++
    $script:Steps += [pscustomobject]@{
        Order     = $Order
        Seq       = $script:StepSeq
        Label     = $Label
        Commands  = @($Commands)
        Note      = $Note
        Apply     = $Apply
        Undo      = @($Undo)
        IsInstall = [bool] $IsInstall
        Unit      = [bool] $Unit
    }
}

function Write-Finding {
    param(
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')] [string] $Status,
        [string] $Check,
        [string] $Detail,
        [string] $Remedy,
        # Machine-runnable commands that fix this finding. Collected into the
        # final block as well as being available inline. A step with no
        # commands but a -FixNote is rendered as an instruction (re-inserting a
        # token is a real step, but it is not a command).
        [string[]] $Fix = @(),
        [string] $FixLabel,
        [string] $FixNote,
        [int] $FixOrder = 50,
        [scriptblock] $FixApply,
        [string[]] $FixUndo = @(),
        [switch] $FixIsInstall
    )
    $colour = 'Gray'
    if ($Status -eq 'PASS') { $colour = 'Green' }
    elseif ($Status -eq 'WARN') { $colour = 'Yellow' }
    elseif ($Status -eq 'FAIL') { $colour = 'Red' }

    Write-Host ('  [{0}] ' -f $Status) -ForegroundColor $colour -NoNewline
    Write-Host ('{0}' -f $Check) -ForegroundColor White
    if ($Detail) { Write-Host ('         {0}' -f $Detail) -ForegroundColor Gray }
    if ($Remedy) { Write-Host ('         -> {0}' -f $Remedy) -ForegroundColor Cyan }

    $script:Findings += [pscustomobject]@{ Status = $Status; Check = $Check }

    # Only a finding that actually needs acting on contributes a step. A PASS
    # never does, so the final block lists what this run found wrong and
    # nothing else.
    if (($Status -eq 'FAIL' -or $Status -eq 'WARN') -and (@($Fix).Count -gt 0 -or $FixNote)) {
        $label = $FixLabel
        if (-not $label) { $label = $Check }
        Add-Step -Order $FixOrder -Label $label -Commands $Fix -Note $FixNote `
            -Apply $FixApply -Undo $FixUndo -IsInstall:$FixIsInstall
    }
}

<#
    Render the consolidated to-do list.

    Steps come from the checks (Write-Finding -Fix), sorted by dependency rank
    and then by the order they were found, so running the block top to bottom
    works: install, register the certificate, settings, Pageant, connect.

    Commands may contain the token <THUMBPRINT>, substituted here. That exists
    because the agent-related checks run before the card is read, so at the
    moment Pageant is found not to be running the thumbprint is not yet known.
    Everything else is resolved where it is discovered.
#>
function Show-CommandBlock {
    param(
        [string[]] $ConnectCommands = @(),
        [string] $ConnectLabel,
        [string] $Thumbprint
    )

    Write-Section (T 'sec.commands')

    $steps = @($script:Steps | Sort-Object Order, Seq)

    if (@($steps).Count -eq 0 -and @($ConnectCommands).Count -gt 0) {
        Write-Host ('  ' + (T 'block.nothingtofix')) -ForegroundColor Green
    } else {
        Write-Host ('  ' + (T 'block.copyrun')) -ForegroundColor Gray
    }
    Write-Host ''

    $n = 0
    foreach ($s in $steps) {
        $n++
        Write-Host ('  {0}. {1}' -f $n, $s.Label) -ForegroundColor White
        if ($s.Note) {
            Write-Host ('       {0}' -f $s.Note) -ForegroundColor Gray
        }

        $cmds = @($s.Commands)
        if ($s.Unit -and @($cmds).Count -gt 1) {
            Write-Host ('       ' + (T 'block.unit')) -ForegroundColor DarkGray
        } elseif (@($cmds).Count -gt 1) {
            Write-Host ('       ' + (T 'block.separate')) -ForegroundColor DarkGray
        }

        $i = 0
        foreach ($c in $cmds) {
            $i++
            $line = $c
            if ($Thumbprint) { $line = $line -replace '<THUMBPRINT>', $Thumbprint }
            if (@($cmds).Count -gt 1 -and -not $s.Unit) {
                Write-Host ('       {0}) {1}' -f [char]([int][char]'a' + $i - 1), $line) -ForegroundColor Cyan
            } else {
                Write-Host ('       {0}' -f $line) -ForegroundColor Cyan
            }
        }
        Write-Host ''
    }

    if (@($ConnectCommands).Count -gt 0) {
        $n++
        $label = $ConnectLabel
        if (-not $label) { $label = T 'block.connect' }
        Write-Host ('  {0}. {1}' -f $n, $label) -ForegroundColor White
        foreach ($c in $ConnectCommands) {
            Write-Host ('       {0}' -f $c) -ForegroundColor Green
        }
        Write-Host ''
    }
}

# --------------------------------------------------------------------------
# Applying changes (-Launch only)
# --------------------------------------------------------------------------

# Every change -Launch makes is recorded here with the command that reverses it,
# and the list is printed at the end. The Linux half of this project backs up,
# validates and can roll back; the least the Windows half can do is say exactly
# what it touched.
$script:Applied = @()

function Add-ChangeRecord {
    param([string] $What, [string[]] $Undo = @())
    $script:Applied += [pscustomobject]@{ What = $What; Undo = @($Undo) }
}

# All writes below are per-user: HKCU, the user's own certificate store, and the
# per-user Startup folder. None needs administrator rights. A write that fails
# for access reasons is reported as a failure rather than retried with
# elevation -- the script's header promises the checks need no admin, and
# silently prompting for it would make that a lie.
function Set-RegDwordChecked {
    param([string] $SubKey, [string] $Name, [int] $Value)

    $old = $null
    try {
        $read = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($SubKey)
        if ($read -and (@($read.GetValueNames()) -contains $Name)) { $old = [int] $read.GetValue($Name) }
    } catch {
        Write-Verbose ('could not read {0}\{1} before writing' -f $SubKey, $Name)
    }

    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($SubKey)
        if (-not $key) { throw 'CreateSubKey returned nothing' }
        $key.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]::DWord)
    } catch {
        return [pscustomobject]@{ Ok = $false; Error = $_.Exception.Message; Old = $old; ReadBack = $null }
    }

    # Read back. "I wrote it" is not evidence that it is set.
    $back = $null
    try {
        $verify = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($SubKey)
        if ($verify -and (@($verify.GetValueNames()) -contains $Name)) { $back = [int] $verify.GetValue($Name) }
    } catch {
        Write-Verbose ('could not read back {0}\{1}' -f $SubKey, $Name)
    }

    $undo = @()
    if ($null -eq $old) {
        $undo = @(('reg delete "HKCU\{0}" /v {1} /f' -f $SubKey, $Name))
    } else {
        $undo = @(('reg add "HKCU\{0}" /v {1} /t REG_DWORD /d {2} /f' -f $SubKey, $Name, $old))
    }

    return [pscustomobject]@{
        Ok       = ($back -eq $Value)
        Error    = $(if ($back -eq $Value) { $null } else { ('read back {0}, expected {1}' -f $back, $Value) })
        Old      = $old
        ReadBack = $back
        Undo     = $undo
    }
}

# The shortcut command as ONE pasteable line. The three-statement form shares
# the $s variable between lines, so pasting it a line at a time into a fresh
# prompt fails on the second line. Semicolons keep it a single unit.
function Get-ShortcutOneLiner {
    param([string] $ShortcutPath, [string] $Target, [string] $Arguments)
    return ('$s=(New-Object -ComObject WScript.Shell).CreateShortcut("{0}"); $s.TargetPath="{1}"; $s.Arguments="{2}"; $s.Save()' -f `
        $ShortcutPath, $Target, $Arguments)
}

function Set-StartupShortcutChecked {
    param([string] $ShortcutPath, [string] $Target, [string] $Arguments)

    $existed = Test-Path -LiteralPath $ShortcutPath
    $backup = $null
    if ($existed) {
        $backup = $ShortcutPath + '.bak'
        try { Copy-Item -LiteralPath $ShortcutPath -Destination $backup -Force } catch { $backup = $null }
    }

    try {
        $shell = New-Object -ComObject WScript.Shell
        $sc = $shell.CreateShortcut($ShortcutPath)
        $sc.TargetPath = $Target
        $sc.Arguments = $Arguments
        $sc.Save()
    } catch {
        return [pscustomobject]@{ Ok = $false; Error = $_.Exception.Message; Undo = @() }
    }

    # Read it back through a fresh COM object, not from what we just set.
    $ok = $false
    $detail = $null
    try {
        $shell2 = New-Object -ComObject WScript.Shell
        $check = $shell2.CreateShortcut($ShortcutPath)
        $ok = ($check.TargetPath -eq $Target -and $check.Arguments.Trim() -eq $Arguments.Trim())
        $detail = ('target={0} args={1}' -f $check.TargetPath, $check.Arguments)
    } catch {
        $detail = 'could not read the shortcut back'
    }

    $undo = @()
    if ($existed -and $backup) {
        $undo = @(('Move-Item -LiteralPath "{0}" -Destination "{1}" -Force' -f $backup, $ShortcutPath))
    } else {
        $undo = @(('Remove-Item -LiteralPath "{0}"' -f $ShortcutPath))
    }

    return [pscustomobject]@{
        Ok     = $ok
        Error  = $(if ($ok) { $null } else { $detail })
        Undo   = $undo
    }
}

<#
    -Launch: apply, verify, connect.

    Order of business, and none of it is negotiable:

      1. If anything has to be INSTALLED, stop. Installing is a change to the
         machine, usually needs elevation, and is not what "configure what is
         already here" means. Print the command, change nothing, exit.
      2. Apply the steps that carry an Apply block, in dependency order.
         A step without one is reported as "cannot be applied automatically"
         rather than skipped in silence.
      3. Re-read what was written. Every apply helper verifies by reading the
         value back, not by trusting that SetValue returned. Connecting on the
         strength of "I just wrote it" is the false-PASS pattern this whole
         project exists to avoid.
      4. Connect only if the re-check passed.
      5. Print what changed and how to reverse it.
#>
function Invoke-Launch {
    param([string] $ConnectCommand, [string] $PuttyExe)

    Write-Section (T 'sec.applying')

    $steps = @($script:Steps | Sort-Object Order, Seq)
    $installs = @($steps | Where-Object { $_.IsInstall })

    if (@($installs).Count -gt 0) {
        Write-Host ('  ' + (T 'launch.stopinstall')) -ForegroundColor Red
        Write-Host ('  ' + (T 'launch.noinstall1')) -ForegroundColor Yellow
        Write-Host ('  ' + (T 'launch.noinstall2')) -ForegroundColor Yellow
        Write-Host ('  ' + (T 'launch.noinstall3')) -ForegroundColor Yellow
        Write-Host ''
        foreach ($s in $installs) {
            Write-Host ('    {0}' -f $s.Label) -ForegroundColor White
            foreach ($c in @($s.Commands)) { Write-Host ('      {0}' -f $c) -ForegroundColor Cyan }
            if ($s.Note) { Write-Host ('      {0}' -f $s.Note) -ForegroundColor Gray }
        }
        Write-Host ''
        Write-Host ('  ' + (T 'launch.installthenrerun')) -ForegroundColor Red
        Write-Host ''
        return 3
    }

    $actionable = @($steps | Where-Object { -not $_.IsInstall })
    $failed = 0

    if (@($actionable).Count -eq 0) {
        Write-Host ('  ' + (T 'launch.nothingtoapply')) -ForegroundColor Green
    }

    foreach ($s in $actionable) {
        if (-not $s.Apply) {
            Write-Host ('  ' + (T 'launch.skip' @($s.Label))) -ForegroundColor Yellow
            Write-Host ('         ' + (T 'launch.skip.why1')) -ForegroundColor Gray
            Write-Host ('         ' + (T 'launch.skip.why2')) -ForegroundColor Gray
            foreach ($c in @($s.Commands)) {
                $line = $c -replace '<THUMBPRINT>', $script:ChosenThumbprint
                Write-Host ('           {0}' -f $line) -ForegroundColor Cyan
            }
            $failed++
            continue
        }

        $result = $null
        try {
            $result = & $s.Apply
        } catch {
            Write-Host ('  ' + (T 'launch.fail' @($s.Label))) -ForegroundColor Red
            Write-Host ('         {0}' -f $_.Exception.Message) -ForegroundColor Red
            $failed++
            continue
        }

        if ($result -and $result.Ok) {
            Write-Host ('  ' + (T 'launch.done' @($s.Label))) -ForegroundColor Green
            $undo = @()
            if ($result.PSObject.Properties.Name -contains 'Undo') { $undo = @($result.Undo) }
            if (@($undo).Count -eq 0) { $undo = @($s.Undo) }
            Add-ChangeRecord -What $s.Label -Undo $undo
            foreach ($u in $undo) {
                Write-Host ('         ' + (T 'launch.undo' @($u))) -ForegroundColor DarkGray
            }
        } else {
            $msg = T 'launch.noresult'
            if ($result -and $result.PSObject.Properties.Name -contains 'Error' -and $result.Error) { $msg = $result.Error }
            Write-Host ('  ' + (T 'launch.fail' @($s.Label))) -ForegroundColor Red
            Write-Host ('         {0}' -f $msg) -ForegroundColor Red
            Write-Host ('         ' + (T 'launch.denied1')) -ForegroundColor Gray
            Write-Host ('         ' + (T 'launch.denied2')) -ForegroundColor Gray
            $failed++
        }
    }

    Write-Host ''
    Show-AppliedSummary

    if ($failed -gt 0) {
        Write-Host ('  ' + (T 'launch.failedcount' @($failed))) -ForegroundColor Red
        Write-Host ('  ' + (T 'launch.fixthose')) -ForegroundColor Yellow
        Write-Host ''
        return 4
    }

    # Re-check: read the state back rather than assume the writes took.
    Write-Host ('  ' + (T 'launch.rechecking')) -ForegroundColor White
    $recheck = Test-LaunchPreconditions
    foreach ($line in $recheck.Lines) {
        Write-Host ('    {0}' -f $line) -ForegroundColor Gray
    }
    if (-not $recheck.Ok) {
        Write-Host ''
        Write-Host ('  ' + (T 'launch.recheckfailed')) -ForegroundColor Red
        Write-Host ''
        return 5
    }
    Write-Host ('  ' + (T 'launch.recheckok')) -ForegroundColor Green
    Write-Host ''

    if (-not $PuttyExe -or -not (Test-Path -LiteralPath $PuttyExe)) {
        Write-Host ('  ' + (T 'launch.nothingtostart')) -ForegroundColor Red
        return 6
    }

    Write-Host ('  ' + (T 'launch.starting' @($ConnectCommand))) -ForegroundColor Green
    Write-Host ('  ' + (T 'launch.pinprompt')) -ForegroundColor Gray
    Write-Host ''
    try {
        # Argument array rather than a command string, so a path with spaces
        # needs no quoting games.
        $argList = @('-x509off')
        if ($ForwardAgent) { $argList += '-A' }
        $argList += @('-i', ('CAPI:' + $script:ChosenThumbprint), '-l', $script:LaunchUser)
        if ($script:LaunchPort -ne 22) { $argList += @('-P', "$($script:LaunchPort)") }
        $argList += $script:LaunchHost
        Start-Process -FilePath $PuttyExe -ArgumentList $argList | Out-Null
    } catch {
        Write-Host ('  ' + (T 'launch.startfailed' @($_.Exception.Message))) -ForegroundColor Red
        return 7
    }
    return 0
}

# Read back the handful of things -Launch may have changed. Deliberately a
# fresh read of the registry and the filesystem, sharing no state with the
# apply step.
function Test-LaunchPreconditions {
    $lines = @()
    $ok = $true

    $x = Get-PuttyGlobalX509
    if ($null -eq $x -or $x -eq 0) {
        $lines += (T 'recheck.x509ok')
    } else {
        $lines += (T 'recheck.x509bad' @($x)); $ok = $false
    }

    $pre = Get-PageantPreloadConfig
    if ($pre.AutoloadCerts -eq 1) {
        $lines += (T 'recheck.autoloadbad'); $ok = $false
    } else {
        $lines += (T 'recheck.autoloadok')
    }

    if ($script:LaunchSessionKey) {
        $s = Get-PuttySessionAgentSetting -Name $script:LaunchSessionKey
        if ($s.Found -and $s.AgentFwd -eq 1 -and $s.TryAgent -eq 1) {
            $lines += (T 'recheck.sessionok' @($s.KeyName))
        } elseif ($s.Found) {
            $lines += (T 'recheck.sessionbad' @($s.KeyName, $s.AgentFwd, $s.TryAgent))
            $ok = $false
        }
    }

    if ($script:StartupLnk -and (Test-Path -LiteralPath $script:StartupLnk)) {
        try {
            $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($script:StartupLnk)
            if ($sc.Arguments.Trim() -ieq $script:StartupArgs) {
                $lines += (T 'recheck.shortcutok')
            } else {
                $lines += (T 'recheck.shortcutbad' @($sc.Arguments.Trim()))
                $ok = $false
            }
        } catch {
            $lines += (T 'recheck.shortcutunread'); $ok = $false
        }
    }

    return [pscustomobject]@{ Ok = $ok; Lines = $lines }
}

function Show-AppliedSummary {
    if (@($script:Applied).Count -eq 0) {
        Write-Host ('  ' + (T 'launch.nochanges')) -ForegroundColor Gray
        Write-Host ''
        return
    }
    Write-Host ('  ' + (T 'launch.changecount' @(@($script:Applied).Count))) -ForegroundColor White
    foreach ($a in $script:Applied) {
        Write-Host ('    {0}' -f $a.What) -ForegroundColor Gray
        foreach ($u in @($a.Undo)) {
            Write-Host ('      {0}' -f $u) -ForegroundColor Cyan
        }
    }
    Write-Host ''
}

function Write-Section {
    param([string] $Title)
    Write-Host ''
    Write-Host ('== {0} ' -f $Title) -ForegroundColor White -NoNewline
    Write-Host ('=' * [Math]::Max(1, 68 - $Title.Length)) -ForegroundColor DarkGray
}

# Run an external program and capture stdout+stderr as a single string without
# letting a non-zero exit code abort us. certutil in particular returns a
# failure code when *any* card in *any* reader has a problem, while still
# printing complete and useful output for the healthy ones -- so the exit code
# must not be treated as "no data".
function Invoke-Capture {
    param(
        [Parameter(Mandatory = $true)] [string] $FilePath,
        [string[]] $Arguments = @()
    )
    Write-Verbose ('running: {0} {1}' -f $FilePath, ($Arguments -join ' '))
    $text = ''
    $code = $null
    try {
        $text = (& $FilePath @Arguments 2>&1 | Out-String)
        $code = $LASTEXITCODE
    } catch {
        return [pscustomobject]@{ Ok = $false; Text = ''; ExitCode = $null; Error = $_.Exception.Message }
    }
    return [pscustomobject]@{ Ok = $true; Text = $text; ExitCode = $code; Error = $null }
}

# Quote a path for a command line if it contains spaces. Defined here with the
# other helpers rather than beside the connection command, because the Pageant
# check builds a command line long before that point.
function Format-Exe {
    param([string] $Path)
    if ($Path -match '\s') { return '"' + $Path + '"' }
    return $Path
}

function Get-FirstExistingPath {
    param([string[]] $Candidates)
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c }
    }
    return $null
}

# --------------------------------------------------------------------------
# PuTTY discovery, and telling PuTTY-CAC apart from stock PuTTY
# --------------------------------------------------------------------------

function Find-Putty {
    param([string] $Override)

    if ($Override) {
        if (Test-Path -LiteralPath $Override -PathType Leaf) { return $Override }
        return $null
    }

    # Standard install locations, all built from environment variables so that
    # nothing here is specific to one machine or one user profile.
    $roots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        (Join-Path $env:LOCALAPPDATA 'Programs'),
        $env:ProgramW6432
    ) | Where-Object { $_ }

    $candidates = @()
    foreach ($r in $roots) {
        foreach ($leaf in @('PuTTY-CAC', 'PuTTY CAC', 'PuTTY')) {
            $candidates += (Join-Path (Join-Path $r $leaf) 'putty.exe')
        }
    }

    # PATH last: an install dir we recognise is a better answer than whatever
    # happens to shadow the name.
    $found = Get-FirstExistingPath -Candidates $candidates
    if ($found) { return $found }

    $cmd = Get-Command 'putty.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $null
}

function Test-BinaryContainsAscii {
    param([string] $Path, [string[]] $Needles)

    $result = @{}
    foreach ($n in $Needles) { $result[$n] = $false }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        foreach ($n in $Needles) { $result[$n] = ($text.IndexOf($n) -ge 0) }
    } catch {
        Write-Verbose ('could not scan {0}: {1}' -f $Path, $_.Exception.Message)
    }
    return $result
}

<#
    How stock PuTTY is told apart from PuTTY-CAC.

    Two independent signals, because neither is documented as an API:

    (a) An ASCII scan of putty.exe for the literal string "CAPI:". That prefix
        is the PuTTY-CAC certificate syntax; stock PuTTY has no CAPI backend at
        all, so the string has no reason to be in its image.

    (b) A behavioural probe of plink.exe, which lives next to putty.exe in the
        same install and is a console program, so its output can be captured
        (putty.exe is a GUI program and answers --help in a message box).
        Running "plink.exe -x509off" with no host prints

            plink: no valid host name provided

        i.e. the option was accepted, whereas an option it does not know gives

            plink: unknown option "-bogusopt"

        Both of those were produced on the test workstation against PuTTY-CAC
        0.85-2, and the two signals agreed. Note that "-x509off" and "CAPI:"
        are NOT listed in "plink --help" output even on PuTTY-CAC, so parsing
        the help text is not a usable test -- that was checked and rejected.

    Honest limitation: both signals were verified POSITIVE against PuTTY-CAC on
    the test workstation. Stock PuTTY was not installed there, so the negative
    side rests on PuTTY-CAC's documented design (CAPI and PKCS#11 are what the
    fork adds) rather than on a measurement. A false "looks like PuTTY-CAC" is
    in any case self-correcting: stock PuTTY would reject -x509off loudly the
    first time the printed command is run.

    The file version ("Release 0.85-2" vs "Release 0.85") and the copyright
    string (PuTTY-CAC's names its fork maintainer alongside Simon Tatham) are
    reported as context only, not used to decide, because both are cosmetic
    fields a repackager can change.
#>
function Test-PuttyCac {
    param([string] $PuttyExe)

    $info = [pscustomobject]@{
        IsCac        = $false
        HowDetected  = @()
        FileVersion  = $null
        Copyright    = $null
        PlinkPath    = $null
        HasCapi      = $false
        HasPkcs      = $false
        HasX509Off   = $false
        ProbeResult  = 'not run'
    }

    try {
        $vi = (Get-Item -LiteralPath $PuttyExe).VersionInfo
        $info.FileVersion = $vi.FileVersion
        $info.Copyright = $vi.LegalCopyright
    } catch {
        Write-Verbose ('no version info for {0}' -f $PuttyExe)
    }

    # (a) string scan
    $scan = Test-BinaryContainsAscii -Path $PuttyExe -Needles @('CAPI:', 'PKCS:', 'x509off')
    $info.HasCapi = $scan['CAPI:']
    $info.HasPkcs = $scan['PKCS:']
    $info.HasX509Off = $scan['x509off']
    if ($info.HasCapi) {
        $info.IsCac = $true
        $info.HowDetected += (T 'detect.capi')
    }

    # (b) behavioural probe via plink
    $plink = Join-Path (Split-Path -Parent $PuttyExe) 'plink.exe'
    if (Test-Path -LiteralPath $plink -PathType Leaf) {
        $info.PlinkPath = $plink
        # No host is given, so no connection is attempted; plink exits on the
        # missing hostname either way. This starts no network traffic.
        $probe = Invoke-Capture -FilePath $plink -Arguments @('-x509off')
        if ($probe.Ok) {
            if ($probe.Text -match 'unknown option') {
                $info.ProbeResult = T 'detect.probe.rejected'
                $info.IsCac = $false
                $info.HowDetected = @((T 'detect.plink.rejected'))
            } elseif ($probe.Text -match 'no valid host name|no hostname|host name') {
                $info.ProbeResult = T 'detect.probe.accepted'
                $info.IsCac = $true
                if ($info.HowDetected -notcontains (T 'detect.plink.accepted')) {
                    $info.HowDetected += (T 'detect.plink.accepted')
                }
            } else {
                $info.ProbeResult = T 'detect.probe.inconclusive'
            }
        } else {
            $info.ProbeResult = T 'detect.probe.norun'
        }
    }

    return $info
}

# --------------------------------------------------------------------------
# Pageant and agent forwarding
# --------------------------------------------------------------------------

<#
    Is Pageant running and serving?

    The authoritative signal is Pageant's named pipe, because that is the
    endpoint PuTTY and plink actually connect to. This build formats it as

        \\.\pipe\pageant.<user>.<64 hex>

    which matches the format string "pageant.%s.%s" found in both pageant.exe
    and putty.exe. On the test workstation the live pipe was present while
    Pageant ran, and enumerating \\.\pipe\ returned it among ~510 pipes on both
    PowerShell 5.1 and 7.

    What this deliberately does NOT look for: \\.\pipe\openssh-ssh-agent, the
    Windows OpenSSH agent pipe. This Pageant does not implement it -- the
    string "openssh-ssh-agent" is absent from both pageant.exe and putty.exe,
    checked by scanning the images. Looking for that pipe would report "no
    agent" on a perfectly healthy Pageant, or find the unrelated Windows
    ssh-agent service and report success when Pageant is not running at all.

    The process name is reported as corroboration only. A process called
    "pageant" that is not serving a pipe cannot answer a signing request, so
    the pipe is what decides.
#>
function Test-PageantRunning {
    $info = [pscustomobject]@{
        Serving     = $false
        PipeName    = $null
        PipeMasked  = $null
        ProcessPath = $null
        HowDetected = 'no pageant pipe found'
    }

    try {
        $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\')
        foreach ($p in $pipes) {
            $leaf = $p.Substring($p.LastIndexOf('\') + 1)
            if ($leaf -match '^pageant\.') {
                $info.Serving = $true
                $info.PipeName = $p
                # The pipe name embeds the Windows account name. Masked when
                # printed, so that a pasted transcript does not carry it.
                $info.PipeMasked = ($leaf -replace '^(pageant\.)[^.]+\.(.{8}).*$', '$1<user>.$2...')
                $info.HowDetected = 'named pipe pageant.<user>.<hash> is being served'
                break
            }
        }
    } catch {
        Write-Verbose ('could not enumerate named pipes: {0}' -f $_.Exception.Message)
        $info.HowDetected = 'could not enumerate named pipes'
        return $info
    }

    $proc = Get-Process -Name 'pageant' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proc) {
        try { $info.ProcessPath = $proc.Path } catch { $info.ProcessPath = '(path unavailable)' }
    }

    return $info
}

<#
    Read a saved session's agent settings.

    Measured value names and kinds, from an existing saved session on the test
    workstation:

        AgentFwd  REG_DWORD   1   -- forward the agent for this session
        TryAgent  REG_DWORD   1   -- use Pageant at all (default 1 when absent)

    Both names also appear as literals in putty.exe and pageant.exe.

    PuTTY percent-encodes awkward characters in session names when it makes the
    registry key, so the key name is not always the session name typed in the
    UI. Rather than reimplement that encoding and get it subtly wrong, this
    matches the literal name against the actual subkey names, then against a
    space-encoded form, and otherwise reports the session as not found and
    lists what does exist.
#>
function Get-PuttySessionAgentSetting {
    param([string] $Name)

    $result = [pscustomobject]@{
        Found      = $false
        KeyName    = $null
        RegPath    = $null
        AgentFwd   = $null
        TryAgent   = $null
        Available  = @()
    }

    $sessionsPath = 'Software\SimonTatham\PuTTY\Sessions'
    $root = $null
    try {
        $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($sessionsPath)
    } catch {
        Write-Verbose 'could not open the PuTTY Sessions registry key'
    }
    if (-not $root) { return $result }

    $names = @($root.GetSubKeyNames())
    $result.Available = $names

    $match = $null
    foreach ($n in $names) {
        if ($n -eq $Name) { $match = $n; break }
    }
    if (-not $match) {
        foreach ($n in $names) {
            if ($n -ieq $Name -or $n -ieq ($Name -replace ' ', '%20')) { $match = $n; break }
        }
    }
    if (-not $match) { return $result }

    $result.Found = $true
    $result.KeyName = $match
    # Verified that reg.exe accepts this form: "reg query
    # HKCU\Software\SimonTatham\PuTTY\Sessions\<name> /v AgentFwd" returns the
    # value, so the "reg add" offered to the operator is a working command.
    $result.RegPath = 'HKCU\{0}\{1}' -f $sessionsPath, $match

    try {
        $key = $root.OpenSubKey($match)
        if ($key) {
            $present = @($key.GetValueNames())
            if ($present -contains 'AgentFwd') { $result.AgentFwd = [int] $key.GetValue('AgentFwd') }
            # TryAgent defaults to 1 (use Pageant) when the value is absent.
            if ($present -contains 'TryAgent') {
                $result.TryAgent = [int] $key.GetValue('TryAgent')
            } else {
                $result.TryAgent = 1
            }
        }
    } catch {
        Write-Verbose ('could not read values for session {0}' -f $match)
    }

    return $result
}

# The global X.509 switch, for information. Measured on the test workstation as
# a REG_DWORD named AuthX509 directly under the PuTTY root -- NOT under the
# per-session key, which is the mechanical reason -x509off behaves as a global,
# persistent setting shared with Pageant rather than a per-session one.
function Get-PuttyGlobalX509 {
    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\SimonTatham\PuTTY')
        if ($key -and (@($key.GetValueNames()) -contains 'AuthX509')) {
            return [int] $key.GetValue('AuthX509')
        }
    } catch {
        Write-Verbose 'could not read AuthX509'
    }
    return $null
}

<#
    Pageant's certificate-preloading configuration.

    Three values, all directly under the PuTTY root (not a session key),
    measured on the test workstation:

        AutoloadCerts        REG_DWORD        enumerate the whole store at start
        SaveCertListEnabled  REG_DWORD        remember a list across restarts
        SaveCertList         REG_MULTI_SZ     the list, entries "CAPI:<sha1>"
                                              with lowercase hex, no separators

    All three value names, and the switches -savecertlist/-savecertlistoff,
    -autoload/-autoloadoff, -forcepincache/-forcepincacheoff and
    -certauthprompting/-certauthpromptingoff, were confirmed present as literals
    in pageant.exe.

    THE TRAP, and the reason this check exists:

    -autoload does NOT mean "load the saved list". It enumerates the ENTIRE
    Windows certificate store and REWRITES SaveCertList on every start. On the
    test workstation that produced 18 entries, including certificates whose key
    containers are dead ("Missing stored keyset"). Pinning the list to a single
    entry and restarting Pageant with no arguments gave 18 again, so trimming
    the list by hand is futile while AutoloadCerts = 1.

    That is not a tidiness problem. The agent offers keys to the server ONE AT
    A TIME, and OpenSSH's default MaxAuthTries is 6. With a store full of
    certificates the right key may never be reached, and the failure surfaces
    as "Server refused our key" -- the same four words produced by the X.509
    trap and by a stale store entry. Three distinct causes, one message.
#>
function Get-PageantPreloadConfig {
    $info = [pscustomobject]@{
        Readable        = $false
        AutoloadCerts   = $null
        SaveListEnabled = $null
        EntryCount      = $null
    }
    try {
        $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\SimonTatham\PuTTY')
        if (-not $key) { return $info }
        $info.Readable = $true
        $present = @($key.GetValueNames())
        if ($present -contains 'AutoloadCerts') { $info.AutoloadCerts = [int] $key.GetValue('AutoloadCerts') }
        if ($present -contains 'SaveCertListEnabled') { $info.SaveListEnabled = [int] $key.GetValue('SaveCertListEnabled') }
        if ($present -contains 'SaveCertList') {
            $list = $key.GetValue('SaveCertList')
            if ($null -ne $list) { $info.EntryCount = @($list).Count }
        }
    } catch {
        Write-Verbose ('could not read Pageant preload configuration: {0}' -f $_.Exception.Message)
    }
    return $info
}

# --------------------------------------------------------------------------
# Card discovery
# --------------------------------------------------------------------------

<#
    Parse "certutil -scinfo -silent".

    Deliberately ASCII-only pattern matching. certutil's output is localised:
    on the test workstation large parts of it came back in Polish. The tokens
    relied on here -- the "Reader:" / "Card:" banners, "Key Container =", and
    "Cert Hash(sha1):" -- stayed in English, and the payloads are GUIDs and hex
    strings, which are locale-independent. Nothing is matched against a word
    that could plausibly be translated out from under us, and a block the parser
    cannot make sense of is reported as unknown rather than guessed at.

    -silent is important: it keeps certutil from putting up a PIN prompt. This
    only ever reads public certificate data; no PIN is needed, asked for or
    stored.
#>
function Get-CardCertificate {
    $certutil = Get-FirstExistingPath -Candidates @(
        (Join-Path $env:SystemRoot 'System32\certutil.exe'),
        (Join-Path $env:SystemRoot 'Sysnative\certutil.exe')
    )
    if (-not $certutil) {
        $c = Get-Command 'certutil.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { $certutil = $c.Source }
    }
    if (-not $certutil) {
        return [pscustomobject]@{ Available = $false; Readers = @(); Certificates = @(); Raw = '' }
    }

    $run = Invoke-Capture -FilePath $certutil -Arguments @('-scinfo', '-silent')
    if (-not $run.Ok -or -not $run.Text) {
        return [pscustomobject]@{ Available = $false; Readers = @(); Certificates = @(); Raw = '' }
    }

    $readers = New-Object System.Collections.ArrayList
    $certs = New-Object System.Collections.ArrayList
    # Readers that actually hold a card. A reader is not a card: an empty
    # reader is still enumerated, and counting readers reported "card present"
    # on a workstation with both tokens unplugged.
    $withCard = New-Object System.Collections.ArrayList

    $currentReader = $null
    $currentCard = $null
    $pendingContainer = $null
    $pendingSubject = $null
    # The CSP that -scinfo names for this card. It is per card, and it is the
    # value "certutil -repairstore -csp" needs: a Crescendo reported
    # "Microsoft Base Smart Card Crypto Provider" where a YubiKey reported
    # "Microsoft Smart Card Key Storage Provider". Guessing it is how the
    # repair silently fails, so it is read rather than assumed.
    $pendingProvider = $null

    foreach ($line in ($run.Text -split "`r?`n")) {

        # "  0: <reader name>" from the "Readers: N" preamble.
        if ($line -match '^\s{2}\d+:\s+(\S.*?)\s*$') {
            $null = $readers.Add($Matches[1])
            continue
        }
        if ($line -match '^---\s*Reader:\s*(\S.*?)\s*$') {
            $currentReader = $Matches[1]; $currentCard = $null; continue
        }
        if ($line -match 'Analyzing card in reader:\s*(\S.*?)\s*$') {
            $currentReader = $Matches[1]; $pendingContainer = $null; continue
        }
        if ($line -match '^---\s+Card:\s*(\S.*?)\s*$') {
            $currentCard = $Matches[1]; continue
        }
        # SCARD_STATE_* are API constants, so they are not translated; the
        # human-readable "No card." beside them is. Match the constant.
        if ($line -match 'SCARD_STATE_PRESENT') {
            if ($currentReader -and -not $withCard.Contains($currentReader)) {
                $null = $withCard.Add($currentReader)
            }
            continue
        }
        if ($line -match 'Key Container\s*=\s*(.+?)\s*(?:\[Default Container\])?\s*$') {
            $pendingContainer = $Matches[1].Trim(); continue
        }
        if ($line -match '^\s*Provider\s*=\s*(\S.*?)\s*$') {
            $pendingProvider = $Matches[1].Trim(); continue
        }
        if ($line -match '^\s*Subject:\s*(\S.*?)\s*$') {
            $pendingSubject = $Matches[1]; continue
        }
        if ($line -match 'Cert Hash\(sha1\):\s*([0-9a-fA-F]{40})') {
            $null = $certs.Add([pscustomobject]@{
                Thumbprint    = $Matches[1].ToUpper()
                Reader        = $currentReader
                Card          = $currentCard
                CardContainer = $pendingContainer
                CardProvider  = $pendingProvider
                Subject       = $pendingSubject
                Source        = 'certutil -scinfo'
            })
            $pendingSubject = $null
            continue
        }
    }

    # The same leaf certificate is echoed several times per card by the chain
    # dump; keep the first sighting of each thumbprint per reader.
    $unique = @()
    $seen = @{}
    foreach ($c in $certs) {
        $key = '{0}|{1}' -f $c.Reader, $c.Thumbprint
        if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $unique += $c }
    }

    return [pscustomobject]@{
        Available     = $true
        Readers       = @($readers)
        ReadersWithCard = @($withCard)
        Certificates  = @($unique)
        Raw           = $run.Text
    }
}

# Containers actually present on the cards, by reader. Used for the key-container
# comparison, which is the check that catches a stale store entry.
function Get-CardContainer {
    param([string] $RawScInfo)

    $map = @{}
    $reader = $null
    foreach ($line in ($RawScInfo -split "`r?`n")) {
        if ($line -match '^---\s*Reader:\s*(\S.*?)\s*$' -or $line -match 'Analyzing card in reader:\s*(\S.*?)\s*$') {
            $reader = $Matches[1]
            if (-not $map.ContainsKey($reader)) { $map[$reader] = @() }
            continue
        }
        if ($line -match 'Key Container\s*=\s*(.+?)\s*(?:\[Default Container\])?\s*$') {
            $guid = $Matches[1].Trim()
            if ($reader) {
                if ($map[$reader] -notcontains $guid) { $map[$reader] += $guid }
            }
        }
    }
    return $map
}

# What the Windows certificate store thinks the key container is, for one
# certificate. The store is the thing that can be wrong, so this is read
# separately from the card and then compared.
function Get-StoreKeyContainer {
    param([string] $Thumb)

    $result = [pscustomobject]@{
        InStore         = $false
        Container       = $null
        MissingKeyset   = $false
        Provider        = $null
    }

    $certutil = Get-FirstExistingPath -Candidates @((Join-Path $env:SystemRoot 'System32\certutil.exe'))
    if (-not $certutil) {
        $c = Get-Command 'certutil.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { $certutil = $c.Source } else { return $result }
    }

    $run = Invoke-Capture -FilePath $certutil -Arguments @('-silent', '-user', '-store', 'My', $Thumb)
    if (-not $run.Ok -or -not $run.Text) { return $result }

    if ($run.Text -match 'Cert Hash\(sha1\):\s*([0-9a-fA-F]{40})') {
        if ($Matches[1].ToUpper() -eq $Thumb.ToUpper()) { $result.InStore = $true }
    }
    # Per line, not against the whole blob: PowerShell's -match leaves $
    # anchored at the end of the string unless (?m) is given, so a pattern
    # ending in \s*$ silently fails to see anything but the last line.
    foreach ($line in ($run.Text -split "`r?`n")) {
        if ($line -match 'Key Container\s*=\s*(.+?)\s*(?:\[Default Container\])?\s*$') {
            $result.Container = $Matches[1].Trim(); break
        }
    }
    # "Missing stored keyset" is certutil's own wording and came back in English
    # even under a localised console; the container comparison below does not
    # depend on it, it is a corroborating signal only.
    if ($run.Text -match 'Missing stored keyset') { $result.MissingKeyset = $true }
    foreach ($line in ($run.Text -split "`r?`n")) {
        if ($line -match 'Provider\s*=\s*(\S.*?)\s*$') { $result.Provider = $Matches[1].Trim(); break }
    }

    return $result
}

# --------------------------------------------------------------------------
# Token family
# --------------------------------------------------------------------------

<#
    Recognise the token family from the reader/card name, and report which
    minidriver INF Windows has bound.

    Only the minidriver *suggestion* is vendor-specific. An unrecognised PIV
    token still goes through every check above and still gets a command line;
    the script just says it does not know which minidriver that vendor ships.

    Get-PnpDevice is guarded: it is absent on older hosts, and it reports
    phantom device nodes for every card the machine has ever seen. Only nodes
    with Status 'OK' are a card that is present now -- on the test workstation
    thirteen smart card nodes were listed and only two were OK.
#>
function Get-TokenFamily {
    param([string] $Name)

    if (-not $Name) {
        return [pscustomobject]@{ Family = 'Unknown'; Display = (T 'token.generic') }
    }
    if ($Name -match 'Yubico|YubiKey') {
        return [pscustomobject]@{ Family = 'Yubico'; Display = 'Yubico YubiKey' }
    }
    # Matched on the card/token product name only. A *reader* brand is
    # deliberately not matched: a contact reader can hold any vendor's card, so
    # inferring the token family from the reader model would misclassify a
    # third-party card sitting in that vendor's reader.
    if ($Name -match 'Crescendo') {
        return [pscustomobject]@{ Family = 'HIDCrescendo'; Display = 'HID Crescendo' }
    }
    return [pscustomobject]@{ Family = 'Unknown'; Display = (T 'token.generic') }
}

function Get-BoundMinidriver {
    if (-not (Get-Command 'Get-PnpDevice' -ErrorAction SilentlyContinue)) {
        Write-Verbose 'Get-PnpDevice not available; minidriver binding unknown'
        return $null
    }
    $rows = @()
    try {
        $devices = Get-PnpDevice -Class SmartCard -ErrorAction Stop |
                   Where-Object { $_.Status -eq 'OK' }
    } catch {
        Write-Verbose ('Get-PnpDevice failed: {0}' -f $_.Exception.Message)
        return $null
    }
    foreach ($d in $devices) {
        $inf = $null
        try {
            $prop = Get-PnpDeviceProperty -InstanceId $d.InstanceId `
                        -KeyName 'DEVPKEY_Device_DriverInfPath' -ErrorAction Stop
            $inf = $prop.Data
        } catch {
            Write-Verbose ('no INF property for {0}' -f $d.InstanceId)
        }
        $rows += [pscustomobject]@{
            FriendlyName = $d.FriendlyName
            Inf          = $inf
            Kind         = (Get-MinidriverKind -Inf $inf)
        }
    }
    return $rows
}

function Get-MinidriverKind {
    param([string] $Inf)
    if (-not $Inf) { return (T 'minidriver.unknown') }
    if ($Inf -match '^msclmd\.inf$') { return (T 'minidriver.inbox') }
    if ($Inf -match '^scunknown\.inf$') { return (T 'minidriver.none') }
    if ($Inf -match '^oem\d+\.inf$') { return (T 'minidriver.vendor' @($Inf)) }
    return (T 'minidriver.other' @($Inf))
}

# --------------------------------------------------------------------------
# OpenSC
# --------------------------------------------------------------------------

function Find-OpenSC {
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) | Where-Object { $_ }
    $info = [pscustomobject]@{
        Pkcs11Tool = $null
        OpenScTool = $null
        Module     = $null
    }
    foreach ($r in $roots) {
        $base = Join-Path $r 'OpenSC Project\OpenSC'
        if (-not $info.Pkcs11Tool) {
            $info.Pkcs11Tool = Get-FirstExistingPath -Candidates @((Join-Path $base 'tools\pkcs11-tool.exe'))
        }
        if (-not $info.OpenScTool) {
            $info.OpenScTool = Get-FirstExistingPath -Candidates @((Join-Path $base 'tools\opensc-tool.exe'))
        }
        if (-not $info.Module) {
            $info.Module = Get-FirstExistingPath -Candidates @((Join-Path $base 'pkcs11\opensc-pkcs11.dll'))
        }
    }
    if (-not $info.Pkcs11Tool) {
        $c = Get-Command 'pkcs11-tool.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { $info.Pkcs11Tool = $c.Source }
    }
    return $info
}

# Read the public certificate objects off the card through PKCS#11 and hash
# them, as an independent source for the thumbprint. Public objects only: no
# PIN is needed, requested or logged, and no private key is read or exported.
function Get-OpenScCardCertificate {
    param($OpenSC)

    $out = @()
    if (-not $OpenSC.Pkcs11Tool -or -not $OpenSC.Module) { return $out }

    $slots = Invoke-Capture -FilePath $OpenSC.Pkcs11Tool -Arguments @('--module', $OpenSC.Module, '--list-token-slots')
    if (-not $slots.Ok -or -not $slots.Text) { return $out }

    $slotIndex = -1
    $slotNames = @{}
    foreach ($line in ($slots.Text -split "`r?`n")) {
        if ($line -match '^Slot\s+(\d+)\s*\(0x[0-9a-fA-F]+\):\s*(\S.*?)\s*$') {
            $slotIndex++
            $slotNames[$slotIndex] = $Matches[2]
        }
    }

    foreach ($idx in ($slotNames.Keys | Sort-Object)) {
        $objs = Invoke-Capture -FilePath $OpenSC.Pkcs11Tool -Arguments @(
            '--module', $OpenSC.Module, '--slot-index', "$idx", '--list-objects', '--type', 'cert')
        if (-not $objs.Ok) { continue }

        $ids = @()
        foreach ($line in ($objs.Text -split "`r?`n")) {
            if ($line -match '^\s*ID:\s*\S+\s*\(0x([0-9a-fA-F]+)\)') { $ids += $Matches[1] }
        }
        foreach ($id in $ids) {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('sc-cert-' + [guid]::NewGuid().ToString() + '.der')
            $read = Invoke-Capture -FilePath $OpenSC.Pkcs11Tool -Arguments @(
                '--module', $OpenSC.Module, '--slot-index', "$idx",
                '--read-object', '--type', 'cert', '--id', $id, '--output-file', $tmp)
            if ($read.Ok -and (Test-Path -LiteralPath $tmp)) {
                try {
                    $hash = (Get-FileHash -LiteralPath $tmp -Algorithm SHA1).Hash.ToUpper()
                    $out += [pscustomobject]@{
                        Thumbprint = $hash
                        Reader     = $slotNames[$idx]
                        Source     = 'OpenSC pkcs11-tool'
                    }
                } catch {
                    Write-Verbose ('could not hash {0}' -f $tmp)
                }
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            }
        }
    }
    return $out
}

# --------------------------------------------------------------------------
# PIN and touch policy
# --------------------------------------------------------------------------

function Find-Ykman {
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) |
             Where-Object { $_ }
    foreach ($r in $roots) {
        $p = Join-Path $r 'Yubico\YubiKey Manager CLI\ykman.exe'
        if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    }
    $c = Get-Command 'ykman.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { return $c.Source }
    return $null
}

<#
    Read the PIN and touch policy of the PIV slot holding a given certificate.

    Two steps, because neither alone is enough:

      1. "ykman piv info" prints a block per slot, each carrying a
         "Fingerprint:" line. That fingerprint is the certificate's SHA-256 --
         verified on the test workstation by hashing the certificate from the
         Windows store and comparing: the two matched exactly. So the slot is
         found by MATCHING, not by assuming 9A. A card can hold certificates in
         9A, 9C, 9D and 9E, and reporting another slot's policy would be worse
         than reporting none.
      2. "ykman piv keys info <slot>" then prints the two policy lines:
             PIN required for use:   ONCE
             Touch required for use: NEVER

    Per Yubico's documentation the PIN policy is NEVER|ONCE|ALWAYS (plus the
    MATCH-* values on bio keys) and the touch policy is NEVER|ALWAYS|CACHED,
    CACHED being a 15-second window. Both are set at key generation or import
    and there is no documented command to change them afterwards.

    Only YubiKeys can be read this way. For anything else this returns unknown
    rather than inventing a command for a vendor whose tooling we do not know.
#>
function Get-YubikeySlotPolicy {
    param([string] $Thumbprint)

    $result = [pscustomobject]@{
        Ok      = $false
        Reason  = 'nocert'
        Slot    = $null
        Pin     = $null
        Touch   = $null
    }

    $ykman = Find-Ykman
    if (-not $ykman) { $result.Reason = 'noykman'; return $result }

    # The certificate's SHA-256, from the copy in the user's store.
    $sha256 = $null
    try {
        $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction Stop |
                Where-Object { $_.Thumbprint -eq $Thumbprint } |
                Select-Object -First 1
        if ($cert) {
            $hasher = [System.Security.Cryptography.SHA256]::Create()
            $bytes = $hasher.ComputeHash($cert.RawData)
            $sha256 = (($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join '')
        }
    } catch {
        Write-Verbose 'could not read the certificate to compute its SHA-256'
    }
    if (-not $sha256) { $result.Reason = 'nocert'; return $result }

    $info = Invoke-Capture -FilePath $ykman -Arguments @('piv', 'info')
    if (-not $info.Ok -or -not $info.Text) { $result.Reason = 'noykman'; return $result }

    # Walk the slot blocks, remembering the slot whose Fingerprint matches.
    $slot = $null
    $found = $null
    foreach ($line in ($info.Text -split "`r?`n")) {
        if ($line -match '^Slot\s+([0-9A-Fa-f]{2})\s*\(') {
            $slot = $Matches[1].ToUpper(); continue
        }
        if ($line -match '^\s*Fingerprint:\s*([0-9a-fA-F]{64})\s*$') {
            if ($slot -and $Matches[1].ToLower() -eq $sha256) { $found = $slot; break }
        }
    }
    if (-not $found) { $result.Reason = 'noslot'; return $result }

    $keys = Invoke-Capture -FilePath $ykman -Arguments @('piv', 'keys', 'info', $found)
    if (-not $keys.Ok -or -not $keys.Text) { $result.Reason = 'noslot'; return $result }

    foreach ($line in ($keys.Text -split "`r?`n")) {
        if ($line -match '^\s*PIN required for use:\s*(\S.*?)\s*$') { $result.Pin = $Matches[1] }
        if ($line -match '^\s*Touch required for use:\s*(\S.*?)\s*$') { $result.Touch = $Matches[1] }
    }

    $result.Slot = $found
    if ($result.Pin -and $result.Touch) { $result.Ok = $true; $result.Reason = $null }
    else { $result.Reason = 'noslot' }
    return $result
}

<#
    Report the policy, and explain it whether or not it could be read.

    The explanation is the part that answers the operator's question ("should
    sudo not force a PIN prompt? FIDO asks every time"), so it prints
    unconditionally. INFO, never WARN: PIN policy ONCE is the sane and
    overwhelmingly common provisioning, and flagging it as a problem would
    train people to ignore the line.
#>
function Show-PinPolicy {
    param([string] $Thumbprint, [string] $Family)

    if ($Family -eq 'Yubico') {
        $pol = Get-YubikeySlotPolicy -Thumbprint $Thumbprint
        if ($pol.Ok) {
            Write-Finding -Status 'INFO' -Check (T 'pin.check') `
                -Detail (T 'pin.slot' @($pol.Slot, $pol.Pin, $pol.Touch))
        } else {
            $detailKey = 'pin.unknown.nocert'
            $extraKey = $null
            if ($pol.Reason -eq 'noykman') {
                $detailKey = 'pin.unknown.noykman'; $extraKey = 'pin.unknown.noykman.detail'
            } elseif ($pol.Reason -eq 'noslot') {
                $detailKey = 'pin.unknown.noslot'; $extraKey = 'pin.unknown.noslot.detail'
            }
            Write-Finding -Status 'INFO' -Check (T 'pin.check') -Detail (T $detailKey)
            if ($extraKey) {
                Write-Host ('         ' + (T $extraKey)) -ForegroundColor Gray
            }
        }
    } else {
        Write-Finding -Status 'INFO' -Check (T 'pin.check') -Detail (T 'pin.unknown.vendor')
        Write-Host ('         ' + (T 'pin.unknown.vendor.detail')) -ForegroundColor Gray
    }

    Write-Host ''
    Write-Host ('  ' + (T 'pin.why.header')) -ForegroundColor White
    foreach ($k in 1..11) {
        Write-Host ('    ' + (T ('pin.why{0}' -f $k))) -ForegroundColor Gray
    }
    Write-Host ''
}

# --------------------------------------------------------------------------
# Minidriver advice
# --------------------------------------------------------------------------

# Every URL below was fetched and confirmed to resolve before being written
# here. The script itself never contacts any of them, and never downloads or
# installs anything -- it prints them so that the operator can decide.
function Show-MinidriverAdvice {
    param([string] $Family, [string] $TokenName)

    Write-Host ''
    Write-Host '  Minidriver suggestion' -ForegroundColor White

    if ($Family -eq 'Yubico') {
        Write-Host '    Token: Yubico YubiKey' -ForegroundColor Gray
        Write-Host '    Package: YubiKey Smart Card Minidriver' -ForegroundColor Gray
        Write-Host '    Official page: https://www.yubico.com/support/download/smart-card-drivers-tools/' -ForegroundColor Gray
        Write-Host '    winget:  winget install --id Yubico.YubiKeySmartCardMinidriver' -ForegroundColor Gray
        Write-Host '    What it fixes:     certificate enrolment onto the card, PIN' -ForegroundColor Gray
        Write-Host '                       management, and CNG/MMC operations that write' -ForegroundColor Gray
        Write-Host '                       to the card.' -ForegroundColor Gray
        Write-Host '    What it does NOT:  a YubiKey that is already provisioned is' -ForegroundColor Gray
        Write-Host '                       handled by the Windows inbox PIV minidriver' -ForegroundColor Gray
        Write-Host '                       (msclmd.inf) on its own. The minidriver is for' -ForegroundColor Gray
        Write-Host '                       provisioning and management; it is not a cure' -ForegroundColor Gray
        Write-Host '                       for every smart card error, and in particular it' -ForegroundColor Gray
        Write-Host '                       will not repair a stale certificate store entry.' -ForegroundColor Gray
    }
    elseif ($Family -eq 'HIDCrescendo') {
        Write-Host '    Token: HID Crescendo' -ForegroundColor Gray
        Write-Host '    Package: HID Crescendo Minidriver (part of HID''s Crescendo tooling;' -ForegroundColor Gray
        Write-Host '             the Credential Management System client is the separate,' -ForegroundColor Gray
        Write-Host '             larger management product).' -ForegroundColor Gray
        Write-Host '    Install docs: https://docs.hidglobal.com/crescendo-md-v1.3/MiniDriver/install_minidriver.htm' -ForegroundColor Gray
        Write-Host '    Doc home:     https://docs.hidglobal.com/crescendo-tools/MiniDriver/home.htm' -ForegroundColor Gray
        Write-Host '    Download:     HID''s own documentation names www.hidglobal.com/drivers' -ForegroundColor Gray
        Write-Host '                  as the download location. That portal refuses automated' -ForegroundColor Gray
        Write-Host '                  clients, so open it in a browser, or ask your HID' -ForegroundColor Gray
        Write-Host '                  representative. There is no winget package for it.' -ForegroundColor Gray
        Write-Host '    What it fixes:     CNG applications such as the MMC certificates' -ForegroundColor Gray
        Write-Host '                       snap-in being able to update key pairs and' -ForegroundColor Gray
        Write-Host '                       certificates on the card.' -ForegroundColor Gray
        Write-Host '    What it does NOT:  per HID''s own notes, the Windows native PIV' -ForegroundColor Gray
        Write-Host '                       minidriver already suffices to *use* certificates' -ForegroundColor Gray
        Write-Host '                       that are on the card for authentication, signing' -ForegroundColor Gray
        Write-Host '                       and encryption. It will not repair a stale' -ForegroundColor Gray
        Write-Host '                       certificate store entry either.' -ForegroundColor Gray
    }
    else {
        Write-Host ('    Token: {0}' -f $TokenName) -ForegroundColor Gray
        Write-Host '    This vendor is not one the script recognises, so it cannot name' -ForegroundColor Gray
        Write-Host '    the right minidriver -- say so plainly rather than guess. Check the' -ForegroundColor Gray
        Write-Host '    token vendor''s own support site for a Windows smart card minidriver.' -ForegroundColor Gray
        Write-Host '    Note that Windows ships an inbox PIV minidriver (msclmd.inf) which' -ForegroundColor Gray
        Write-Host '    is often enough on its own for a card that is already provisioned,' -ForegroundColor Gray
        Write-Host '    so a missing vendor driver may not be the problem at all.' -ForegroundColor Gray
    }
}

# Add the vendor minidriver install to the to-do list. Only Yubico has a winget
# package -- verified against the live catalogue, as were the other ids used in
# this script. HID ship no package at all, so that step is a note pointing at
# their documented download location rather than a command that does not exist.
function Add-MinidriverStep {
    param([string] $Family, [string] $TokenName)

    if ($Family -eq 'Yubico') {
        Add-Step -Order $script:OrderInstall `
            -Label (T 'fix.minidriver.yubico') `
            -Commands @('winget install --id Yubico.YubiKeySmartCardMinidriver')
    }
    elseif ($Family -eq 'HIDCrescendo') {
        Add-Step -Order $script:OrderInstall `
            -Label (T 'fix.minidriver.hid') `
            -Note 'Download it from www.hidglobal.com/drivers -- HID''s own documentation names that as the location, and the portal refuses automated clients, so open it in a browser or ask your HID representative. Install docs: https://docs.hidglobal.com/crescendo-md-v1.3/MiniDriver/install_minidriver.htm'
    }
    else {
        Add-Step -Order $script:OrderInstall `
            -Label (T 'fix.minidriver.unknown' @($TokenName)) `
            -Note 'This vendor is not one the script recognises, so it cannot name the driver. Check the vendor''s own support site. Windows'' inbox PIV minidriver (msclmd.inf) is often enough on its own for an already-provisioned card, so this may not be the problem at all.'
    }
}

# How to re-run this script, for the "then re-run" step. Rebuilt from the real
# invocation so that the operator's own switches survive the round trip.
#
# NB: it reads $script:InvokedWith, captured at script scope, NOT
# $PSBoundParameters. Inside a function that automatic variable holds the
# *function's* own bound parameters, which here is always empty -- the first
# version of this printed the script path with every argument silently dropped.
function Get-SelfInvocation {
    $self = $script:SelfPath
    if (-not $self) { $self = '.\New-SmartCardSshCommand.ps1' }
    $parts = @((Format-Exe $self))
    foreach ($kv in $script:InvokedWith.GetEnumerator()) {
        $v = $kv.Value
        if ($v -is [switch]) {
            if ($v.IsPresent) { $parts += ('-{0}' -f $kv.Key) }
        } else {
            $parts += ('-{0} {1}' -f $kv.Key, (Format-Exe ([string] $v)))
        }
    }
    return ($parts -join ' ')
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

# Catalogue check and nothing else, so it is safe to run anywhere.
if ($SelfTest) {
    exit (Invoke-CatalogueSelfTest)
}

Write-Host ''
Write-Host (T 'hdr.title') -ForegroundColor White
Write-Host ('-' * 42) -ForegroundColor DarkGray
Write-Host (T 'hdr.platform' @($PSVersionTable.PSVersion, [System.Environment]::OSVersion.VersionString)) -ForegroundColor Gray
if ($Launch) {
    Write-Host (T 'hdr.launchmode') -ForegroundColor Yellow
} else {
    Write-Host (T 'hdr.readonly') -ForegroundColor Gray
}
Write-Host (T 'hdr.nokey') -ForegroundColor Gray
Write-Host (T 'hdr.noadmin1') -ForegroundColor Gray
Write-Host (T 'hdr.noadmin2') -ForegroundColor Gray

# ---- 1. dependencies -----------------------------------------------------

Write-Section (T 'sec.dependencies')

$puttyExe = Find-Putty -Override $PuttyPath
$cac = $null

if (-not $puttyExe) {
    Write-Finding -Status 'FAIL' -Check (T 'chk.putty') `
        -Detail (T 'chk.putty.absent') `
        -Remedy (T 'chk.putty.remedy') `
        -FixLabel (T 'fix.putty.install') `
        -FixOrder $script:OrderInstall -FixIsInstall `
        -Fix @('winget install --id NoMoreFood.PuTTY-CAC')
} else {
    $cac = Test-PuttyCac -PuttyExe $puttyExe
    $detail = '{0}  [version: {1}]' -f $puttyExe, $cac.FileVersion
    if ($cac.IsCac) {
        Write-Finding -Status 'PASS' -Check (T 'chk.putty') -Detail $detail
        Write-Host ('         ' + (T 'putty.detectedvia' @(($cac.HowDetected -join '; ')))) -ForegroundColor DarkGray
        Write-Host ('         ' + (T 'putty.probe' @($cac.ProbeResult))) -ForegroundColor DarkGray
        Write-Host ('         CAPI: {0}   PKCS: {1}   x509off: {2}' -f $cac.HasCapi, $cac.HasPkcs, $cac.HasX509Off) -ForegroundColor DarkGray
    } else {
        Write-Finding -Status 'FAIL' -Check (T 'chk.putty') `
            -Detail (T 'chk.putty.stock' @($detail)) `
            -Remedy (T 'chk.putty.remedy.path') `
            -FixLabel (T 'fix.putty.install.stock') `
            -FixOrder $script:OrderInstall -FixIsInstall `
            -Fix @('winget install --id NoMoreFood.PuTTY-CAC')
        Write-Host ('         ' + (T 'putty.probe' @($cac.ProbeResult))) -ForegroundColor DarkGray
    }
}

$opensc = Find-OpenSC
if ($opensc.Pkcs11Tool -and $opensc.OpenScTool) {
    Write-Finding -Status 'PASS' -Check (T 'chk.opensc') `
        -Detail (T 'chk.opensc.found' @((Split-Path -Parent $opensc.Pkcs11Tool)))
} elseif ($opensc.Pkcs11Tool -or $opensc.OpenScTool) {
    Write-Finding -Status 'WARN' -Check (T 'chk.opensc') `
        -Detail (T 'chk.opensc.partial') `
        -Remedy ('winget install --id OpenSC.OpenSC -- ' + (T 'chk.opensc.remedy'))
} else {
    Write-Finding -Status 'WARN' -Check (T 'chk.opensc') `
        -Detail (T 'chk.opensc.absent') `
        -Remedy ('winget install --id OpenSC.OpenSC -- ' + (T 'chk.opensc.remedy'))
}

if ($ForwardAgent -or $SessionName) {

    # --- Pageant itself ---
    $pageant = Test-PageantRunning
    if ($pageant.Serving) {
        Write-Finding -Status 'PASS' -Check (T 'chk.pageant') `
            -Detail (T 'chk.pageant.detail' @($pageant.PipeMasked, $pageant.HowDetected))
        if ($pageant.ProcessPath) {
            Write-Host ('         ' + (T 'pageant.process' @($pageant.ProcessPath))) -ForegroundColor DarkGray
        }
    } else {
        $pageantExe = 'pageant.exe'
        if ($puttyExe) { $pageantExe = Join-Path (Split-Path -Parent $puttyExe) 'pageant.exe' }
        Write-Finding -Status 'FAIL' -Check (T 'chk.pageant') `
            -Detail $pageant.HowDetected `
            -Remedy (T 'chk.pageant.remedy' @($pageantExe)) `
            -FixLabel (T 'fix.pageant.start') `
            -FixOrder $script:OrderAgent `
            -Fix @(('{0} CAPI:<THUMBPRINT>' -f (Format-Exe $pageantExe)))
    }

    Write-Host ('         ' + (T 'pageant.attime1')) -ForegroundColor DarkGray
    Write-Host ('         ' + (T 'pageant.attime2')) -ForegroundColor DarkGray
    Write-Host ('         ' + (T 'pageant.attime3')) -ForegroundColor DarkGray

    # --- per-session agent forwarding ---
    if (-not $SessionName) {
        Write-Finding -Status 'WARN' -Check (T 'chk.session') `
            -Detail (T 'chk.session.nonamegiven') `
            -Remedy (T 'chk.session.nonamegiven.remedy')
    } else {
        $sess = Get-PuttySessionAgentSetting -Name $SessionName
        if (-not $sess.Found) {
            $avail = 'none'
            if (@($sess.Available).Count -gt 0) { $avail = (@($sess.Available) -join ', ') }
            Write-Finding -Status 'WARN' -Check (T 'chk.session') `
                -Detail (T 'chk.session.notfound' @($SessionName, $avail)) `
                -Remedy (T 'chk.session.notfound.remedy')
        } else {
            $fwd = $sess.AgentFwd
            $try = $sess.TryAgent
            $script:LaunchSessionKey = $sess.KeyName
            $script:LaunchNeedAgentFwd = ($fwd -ne 1)
            $script:LaunchNeedTryAgent = ($try -ne 1)
            $fwdText = 'absent (treated as off)'
            if ($null -ne $fwd) { $fwdText = "$fwd" }

            if ($fwd -eq 1 -and $try -eq 1) {
                Write-Finding -Status 'PASS' -Check (T 'chk.session') `
                    -Detail (T 'chk.session.ok' @($sess.KeyName, $fwdText, $try))
            } else {
                $why = @()
                if ($fwd -ne 1) { $why += (T 'chk.session.bad.fwd' @($fwdText)) }
                if ($try -ne 1) { $why += (T 'chk.session.bad.try' @($try)) }
                # Built as a plain array first. Writing the filter as a pipe
                # inside the @( ... ) argument parses on PowerShell 7 but is
                # "An empty pipe element is not allowed" on 5.1, which is the
                # version this has to work on.
                $sessionFix = @()
                if ($fwd -ne 1) { $sessionFix += ('reg add "{0}" /v AgentFwd /t REG_DWORD /d 1 /f' -f $sess.RegPath) }
                if ($try -ne 1) { $sessionFix += ('reg add "{0}" /v TryAgent /t REG_DWORD /d 1 /f' -f $sess.RegPath) }

                Write-Finding -Status 'FAIL' -Check (T 'chk.session') `
                    -Detail (T 'chk.session.bad' @($sess.KeyName, ($why -join '; '))) `
                    -Remedy (T 'chk.session.bad.remedy') `
                    -FixLabel (T 'fix.session.agentfwd' @($sess.KeyName)) `
                    -FixOrder $script:OrderSettings `
                    -Fix $sessionFix `
                    -FixApply {
                        $path = 'Software\SimonTatham\PuTTY\Sessions\' + $script:LaunchSessionKey
                        $r1 = $null; $r2 = $null
                        if ($script:LaunchNeedAgentFwd) { $r1 = Set-RegDwordChecked -SubKey $path -Name 'AgentFwd' -Value 1 }
                        if ($script:LaunchNeedTryAgent) { $r2 = Set-RegDwordChecked -SubKey $path -Name 'TryAgent' -Value 1 }
                        $done = @(@($r1, $r2) | Where-Object { $_ })
                        $bad = @($done | Where-Object { -not $_.Ok })
                        $undo = @($done | ForEach-Object { $_.Undo })
                        if (@($bad).Count -gt 0) {
                            [pscustomobject]@{ Ok = $false; Error = (@($bad | ForEach-Object { $_.Error }) -join '; '); Undo = $undo }
                        } else {
                            [pscustomobject]@{ Ok = $true; Error = $null; Undo = $undo }
                        }
                    }
                # Printed from the same array the fix was built from, so the
                # inline advice and the summarised step cannot disagree.
                Write-Host ''
                foreach ($line in $sessionFix) {
                    Write-Host ('         {0}' -f $line) -ForegroundColor Cyan
                }
                Write-Host ('         ' + (T 'session.nothingunless')) -ForegroundColor DarkGray
            }
            Write-Host ('         ' + (T 'session.anote1')) -ForegroundColor DarkGray
            Write-Host ('         ' + (T 'session.anote2')) -ForegroundColor DarkGray
        }
    }
}

# The global X.509 switch, reported for information because it is the setting
# -x509off manipulates and it persists between runs.
$x509 = Get-PuttyGlobalX509
if ($null -eq $x509) {
    Write-Host ('  [INFO] ' + (T 'x509.unset')) -ForegroundColor Gray
} elseif ($x509 -eq 0) {
    Write-Host ('  [INFO] ' + (T 'x509.off')) -ForegroundColor Gray
} else {
    Write-Host ('  [INFO] ' + (T 'x509.on' @($x509))) -ForegroundColor Yellow
}

# Pageant's preload configuration. Checked unconditionally, not just under
# -ForwardAgent: whenever Pageant is consulted at all (TryAgent defaults to 1)
# an over-full SaveCertList can exhaust the server's MaxAuthTries before the
# card's key is reached, and that failure reads as "Server refused our key".
$preload = Get-PageantPreloadConfig
if (-not $preload.Readable) {
    Write-Host ('  [INFO] ' + (T 'chk.preload.unknown')) -ForegroundColor Gray
} else {
    $countText = T 'preload.notset'
    if ($null -ne $preload.EntryCount) { $countText = T 'preload.entries' @($preload.EntryCount) }

    if ($preload.AutoloadCerts -eq 1) {
        Write-Finding -Status 'WARN' -Check (T 'chk.preload') `
            -Detail (T 'chk.preload.autoload' @($countText)) `
            -Remedy (T 'chk.preload.autoload.remedy') `
            -FixLabel (T 'fix.preload.autoload') `
            -FixOrder $script:OrderPreload `
            -Fix @('reg add "HKCU\Software\SimonTatham\PuTTY" /v AutoloadCerts /t REG_DWORD /d 0 /f') `
            -FixApply { Set-RegDwordChecked -SubKey 'Software\SimonTatham\PuTTY' -Name 'AutoloadCerts' -Value 0 }
        Write-Host ('         ' + (T 'preload.maxauth1')) -ForegroundColor Yellow
        Write-Host ('         ' + (T 'preload.maxauth2')) -ForegroundColor Yellow
        Write-Host ('         ' + (T 'preload.maxauth3')) -ForegroundColor Yellow
        Write-Host ('         ' + (T 'preload.maxauth4')) -ForegroundColor Yellow
    } elseif ($null -eq $preload.AutoloadCerts) {
        Write-Host ('  [INFO] ' + (T 'chk.preload.default' @($countText))) -ForegroundColor Gray
    } else {
        Write-Finding -Status 'PASS' -Check (T 'chk.preload') `
            -Detail (T 'chk.preload.ok' @($countText))
        if ($null -ne $preload.EntryCount -and $preload.EntryCount -gt 1) {
            Write-Host ('         ' + (T 'preload.trim1' @($preload.EntryCount))) -ForegroundColor Yellow
            Write-Host ('         ' + (T 'preload.trim2')) -ForegroundColor Yellow
            Write-Host ('         ' + (T 'preload.trim3')) -ForegroundColor Yellow
        }
    }
}

$card = Get-CardCertificate

if (-not $card.Available) {
    Write-Finding -Status 'FAIL' -Check (T 'chk.reader') `
        -Detail (T 'chk.reader.nooutput') `
        -Remedy (T 'chk.reader.nooutput.remedy')
} elseif (@($card.Readers).Count -eq 0) {
    Write-Finding -Status 'FAIL' -Check (T 'chk.reader') `
        -Detail (T 'chk.reader.noreaders') `
        -Remedy (T 'chk.reader.noreaders.remedy')
} elseif (@($card.ReadersWithCard).Count -eq 0) {
    # A reader is not a card. Counting readers alone reported "card present"
    # on a workstation with both tokens unplugged, which is the kind of green
    # result that sends someone looking at the server.
    Write-Finding -Status 'FAIL' -Check (T 'chk.reader') `
        -Detail (T 'chk.reader.nocard' @(@($card.Readers).Count)) `
        -Remedy (T 'chk.reader.nocard.remedy')
    Write-Host ('         ' + (T 'reader.list' @((@($card.Readers) -join ', ')))) -ForegroundColor Gray
} else {
    Write-Finding -Status 'PASS' -Check (T 'chk.reader') `
        -Detail (T 'chk.reader.ok' @(
            @($card.ReadersWithCard).Count, @($card.Readers).Count,
            (@($card.ReadersWithCard) -join ', ')))
    $empty = @($card.Readers | Where-Object { @($card.ReadersWithCard) -notcontains $_ })
    if ($empty.Count -gt 0) {
        Write-Host ('         ' + (T 'reader.empty' @(($empty -join ', ')))) -ForegroundColor Gray
    }
}

# ---- 2. tokens -----------------------------------------------------------

Write-Section (T 'sec.tokens')

$minidrivers = Get-BoundMinidriver
if ($null -eq $minidrivers) {
    Write-Host ('  ' + (T 'tokens.minidriver.unknown')) -ForegroundColor Yellow
} elseif (@($minidrivers).Count -eq 0) {
    Write-Host ('  ' + (T 'tokens.minidriver.none')) -ForegroundColor Yellow
} else {
    foreach ($m in $minidrivers) {
        $label = [string] $m.FriendlyName
        if ($label.Length -gt 44) { $label = $label.Substring(0, 41) + '...' }
        Write-Host ('  {0,-46} {1}' -f $label, $m.Kind) -ForegroundColor Gray
    }
}

$readerList = @($card.Readers)
# Whether -Reader actually narrowed anything. The certificate section filters
# against $readerList rather than re-deriving the narrowing from $Reader, so the
# two sections cannot end up looking at different sets in the same run --
# measured: with -Reader naming an absent reader, the token section fell back to
# all readers while the certificate section filtered to zero and then reported
# "no certificate could be read from any card", which blamed the card for a
# certificate it had read perfectly well and suggested installing a minidriver.
$readerFilterApplied = $false
if ($Reader) {
    $narrowed = @($readerList | Where-Object { $_ -like ('*' + $Reader + '*') })
    if (@($narrowed).Count -gt 0) {
        $readerList = $narrowed
        $readerFilterApplied = $true
    } else {
        Write-Host ''
        Write-Host ('  ' + (T 'tokens.readernotmatched' @($Reader))) -ForegroundColor Yellow
    }
}

$tokens = @()
foreach ($r in $readerList) {
    $fam = Get-TokenFamily -Name $r
    $certsHere = @(@($card.Certificates) | Where-Object { $_.Reader -eq $r })
    $tokens += [pscustomobject]@{
        Reader       = $r
        Family       = $fam.Family
        Display      = $fam.Display
        Certificates = $certsHere
        HasCard      = (@($card.ReadersWithCard) -contains $r)
    }
}

if (@($tokens).Count -eq 0) {
    Write-Host ('  ' + (T 'tokens.none')) -ForegroundColor Yellow
} else {
    Write-Host ''
    foreach ($t in $tokens) {
        $suffix = if ($t.HasCard) { '' } else { '   (reader empty)' }
        Write-Host ('  {0,-46} {1}{2}' -f $t.Reader, $t.Display, $suffix) -ForegroundColor Gray
    }
    # Count cards, not readers. An empty reader is still enumerated, and
    # announcing "2 tokens are attached" with one card in makes the operator
    # look for an ambiguity that is not there.
    $withCards = @($tokens | Where-Object { $_.HasCard })
    if (@($withCards).Count -gt 1) {
        Write-Host ''
        Write-Host ('  ' + (T 'tokens.multiple1' @(@($withCards).Count))) -ForegroundColor Yellow
        Write-Host ('  ' + (T 'tokens.multiple2')) -ForegroundColor Yellow
        Write-Host ('  ' + (T 'tokens.multiple3')) -ForegroundColor Yellow
    } elseif ($Reader) {
        Write-Host ''
        Write-Host ('  ' + (T 'session.narrowed' @($Reader))) -ForegroundColor Gray
    }
}

# ---- 3. certificates -----------------------------------------------------

Write-Section (T 'sec.certificates')

$cardContainers = @{}
if ($card.Available) { $cardContainers = Get-CardContainer -RawScInfo $card.Raw }

$candidates = @($card.Certificates)

if ($UseOpenSC) {
    $extra = Get-OpenScCardCertificate -OpenSC $opensc
    foreach ($e in $extra) {
        $known = @($candidates | Where-Object { $_.Thumbprint -eq $e.Thumbprint })
        if (@($known).Count -gt 0) {
            Write-Host ('  ' + (T 'opensc.agrees' @($e.Thumbprint, $e.Reader))) -ForegroundColor DarkGray
        } else {
            Write-Host ('  ' + (T 'opensc.extra' @($e.Thumbprint, $e.Reader))) -ForegroundColor Yellow
            $candidates += [pscustomobject]@{
                Thumbprint    = $e.Thumbprint
                Reader        = $e.Reader
                Card          = $null
                CardContainer = $null
                CardProvider  = $null
                Subject       = $null
                Source        = $e.Source
            }
        }
    }
}

if ($readerFilterApplied) {
    # Against the reader list the token section settled on, not against $Reader
    # again. Announced only when the narrowing really happened: saying
    # 'filtered to readers matching "X"' when nothing matched X describes a
    # filter that was not applied.
    $candidates = @($candidates | Where-Object { $_.Reader -and (@($readerList) -contains $_.Reader) })
    Write-Host ('  ' + (T 'cert.filtered' @($Reader, @($candidates).Count))) -ForegroundColor Gray
}
if ($Thumbprint) {
    $wanted = ($Thumbprint -replace '[^0-9a-fA-F]', '').ToUpper()
    $candidates = @($candidates | Where-Object { $_.Thumbprint -eq $wanted })
    if (@($candidates).Count -eq 0) {
        $candidates = @([pscustomobject]@{
            Thumbprint = $wanted; Reader = '(supplied by -Thumbprint)'; Card = $null
            CardContainer = $null; CardProvider = $null; Subject = $null; Source = '-Thumbprint'
        })
    }
}

$usable = @()

if (@($candidates).Count -eq 0) {
    Write-Finding -Status 'FAIL' -Check (T 'chk.cert.none') `
        -Detail (T 'chk.cert.none.detail') `
        -Remedy (T 'chk.cert.none.remedy')
} else {
    foreach ($c in $candidates) {
        Write-Host ''
        Write-Host ('  ' + (T 'cert.heading' @($c.Thumbprint))) -ForegroundColor White
        Write-Host ('    ' + (T 'cert.reader' @($c.Reader))) -ForegroundColor Gray
        Write-Host ('    ' + (T 'cert.source' @($c.Source))) -ForegroundColor Gray
        if ($c.CardContainer) {
            Write-Host ('    ' + (T 'cert.containercard' @($c.CardContainer))) -ForegroundColor Gray
        } else {
            Write-Host ('    ' + (T 'cert.containercard.unknown')) -ForegroundColor Gray
        }

        $store = Get-StoreKeyContainer -Thumb $c.Thumbprint
        if ($store.Container) {
            Write-Host ('    ' + (T 'cert.containerstore' @($store.Container))) -ForegroundColor Gray
        } else {
            Write-Host ('    ' + (T 'cert.containerstore.unknown')) -ForegroundColor Gray
        }

        # The CSP for -repairstore, taken from what -scinfo actually reported
        # for this card. Falls back to the store's own Provider, then to a
        # placeholder -- never to a guessed provider name, because the wrong
        # CSP makes -repairstore fail in a way that looks like a bad card.
        # Computed after $store is read, since that is one of the sources.
        $csp = $c.CardProvider
        if (-not $csp) { $csp = $store.Provider }
        if (-not $csp) { $csp = '<the Provider that -scinfo names for this card>' }

        if (-not $store.InStore) {
            Write-Finding -Status 'FAIL' -Check (T 'chk.cert.instore' @($c.Thumbprint)) `
                -Detail (T 'chk.cert.instore.detail') `
                -Remedy (T 'chk.cert.instore.remedy') `
                -FixLabel (T 'fix.cert.reinsert' @($c.Thumbprint)) `
                -FixOrder $script:OrderRegister `
                -FixNote (T 'fix.cert.reinsert.note')

            # Two genuinely separate commands, run in order, so they are two
            # numbered steps rather than one step with two lines.
            Add-Step -Order $script:OrderRegister `
                -Label (T 'fix.cert.addstore' @($c.Thumbprint)) `
                -Note (T 'fix.cert.addstore.note') `
                -Commands @('certutil -user -addstore My <cert.der>')
            Add-Step -Order $script:OrderRegister `
                -Label (T 'fix.cert.repair' @($c.Thumbprint)) `
                -Note (T 'fix.cert.repair.note') `
                -Commands @(('certutil -user -csp "{0}" -repairstore My {1}' -f $csp, $c.Thumbprint))
            Write-Host '         Re-inserting the token is worth trying first: the propagation' -ForegroundColor Yellow
            Write-Host '         service registers card certificates on an insertion event, so a' -ForegroundColor Yellow
            Write-Host '         certificate written to a card that was already in the reader is' -ForegroundColor Yellow
            Write-Host '         never seen.' -ForegroundColor Yellow
            Write-Host '         If that does not do it, register it by hand. Measured on an HID' -ForegroundColor Yellow
            Write-Host '         Crescendo whose certificate certutil could read but had not' -ForegroundColor Yellow
            Write-Host '         propagated -- read the certificate off the card first, then:' -ForegroundColor Yellow
            Write-Host ('           certutil -user -addstore My <cert.der>') -ForegroundColor Gray
            Write-Host ('           certutil -user -csp "<the Provider from -scinfo>" -repairstore My {0}' -f $c.Thumbprint) -ForegroundColor Gray
            Write-Host '         The CSP must be the one -scinfo names for that card: a Crescendo' -ForegroundColor Yellow
            Write-Host '         reported "Microsoft Base Smart Card Crypto Provider" where a' -ForegroundColor Yellow
            Write-Host '         YubiKey reported the Key Storage Provider. "Encryption test' -ForegroundColor Yellow
            Write-Host '         passed" in the output means the binding took.' -ForegroundColor Yellow
            Write-Host '         Or skip the store entirely: -i PKCS:<id>=<path-to-pkcs11.dll>' -ForegroundColor Yellow
            continue
        }

        # This is the check worth having. A store entry can name a key container
        # that is not on the card -- Windows then reports "the smart card cannot
        # perform the requested operation or the operation requires a different
        # smart card", which is literally true and very hard to read.
        $onCard = @()
        if ($c.Reader -and $cardContainers.ContainsKey($c.Reader)) { $onCard = @($cardContainers[$c.Reader]) }
        if (@($onCard).Count -eq 0) {
            foreach ($k in $cardContainers.Keys) { $onCard += @($cardContainers[$k]) }
        }

        if ($store.MissingKeyset) {
            Write-Finding -Status 'FAIL' -Check (T 'chk.cert.keyset' @($c.Thumbprint)) `
                -Detail (T 'chk.cert.keyset.detail') `
                -Remedy (T 'chk.cert.keyset.remedy') `
                -FixLabel (T 'fix.cert.rebind' @($c.Thumbprint)) `
                -FixOrder $script:OrderRegister `
                -FixNote (T 'fix.cert.rebind.note') `
                -Fix @(('certutil -user -csp "{0}" -repairstore My {1}' -f $csp, $c.Thumbprint))
        } elseif (-not $store.Container -or @($onCard).Count -eq 0) {
            Write-Finding -Status 'WARN' -Check (T 'chk.cert.container' @($c.Thumbprint)) `
                -Detail (T 'chk.cert.container.unknown') `
                -Remedy (T 'chk.cert.container.unknown.remedy')
        } elseif ($onCard -contains $store.Container) {
            Write-Finding -Status 'PASS' -Check (T 'chk.cert.container' @($c.Thumbprint)) `
                -Detail (T 'chk.cert.container.ok' @($store.Container))
            $usable += $c
        } else {
            Write-Finding -Status 'FAIL' -Check (T 'chk.cert.container' @($c.Thumbprint)) `
                -Detail (T 'chk.cert.container.bad' @($store.Container, (@($onCard) -join ', '))) `
                -Remedy (T 'chk.cert.container.bad.remedy')
        }
    }
}

# A view of the store from the other side, because this is where the mess
# accumulates: entries whose key container no longer exists anywhere.
try {
    $storeAll = @(Get-ChildItem Cert:\CurrentUser\My -ErrorAction Stop)
    if (@($storeAll).Count -gt 0) {
        Write-Host ''
        Write-Host ('  ' + (T 'store.count1' @(@($storeAll).Count))) -ForegroundColor Gray
        Write-Host ('  ' + (T 'store.count2')) -ForegroundColor Gray
        Write-Host ('  ' + (T 'store.count3')) -ForegroundColor Gray
    }
} catch {
    Write-Verbose 'could not enumerate Cert:\CurrentUser\My'
}

# ---- 4. the command ------------------------------------------------------

Write-Section (T 'sec.result')

if (@($usable).Count -eq 0) {
    Write-Host ('  ' + (T 'result.nocert')) -ForegroundColor Red

    $family = 'Unknown'
    $tokenName = 'unknown token'
    if (@($tokens).Count -eq 1) {
        $family = $tokens[0].Family; $tokenName = $tokens[0].Reader
    } elseif (@($tokens).Count -gt 1) {
        Write-Host ''
        Write-Host ('  ' + (T 'result.pertoken')) -ForegroundColor Yellow
        foreach ($t in $tokens) { Show-MinidriverAdvice -Family $t.Family -TokenName $t.Reader }
        $family = $null
    }
    if ($family) { Show-MinidriverAdvice -Family $family -TokenName $tokenName }

    # With no certificate to work from, the minidriver and OpenSC installs are
    # the steps that might actually produce one, so they join the list here
    # rather than at their own checks -- where they would be noise on a machine
    # whose card reads fine.
    foreach ($t in $tokens) { Add-MinidriverStep -Family $t.Family -TokenName $t.Reader }
    if (-not ($opensc.Pkcs11Tool -and $opensc.OpenScTool)) {
        Add-Step -Order $script:OrderInstall `
            -Label (T 'fix.opensc.install') `
            -Commands @('winget install --id OpenSC.OpenSC')
    }

    if ($opensc.Pkcs11Tool -and $opensc.Module -and -not $UseOpenSC) {
        Write-Host ''
        Write-Host ('  ' + (T 'result.readoff1')) -ForegroundColor Gray
        Write-Host ('  ' + (T 'result.readoff2')) -ForegroundColor Gray
        Write-Host ('    & "{0}" --module "{1}" --list-token-slots' -f $opensc.Pkcs11Tool, $opensc.Module) -ForegroundColor Gray
    }

    Add-Step -Order $script:OrderConnect `
        -Label (T 'fix.rerun') `
        -Commands @((Get-SelfInvocation))

    Show-CommandBlock
    exit 1
}

if (@($usable).Count -gt 1) {
    Write-Host ('  ' + (T 'result.ambiguous1' @(@($usable).Count))) -ForegroundColor Yellow
    Write-Host ('  ' + (T 'result.ambiguous2')) -ForegroundColor Yellow
    Write-Host ''
    foreach ($u in $usable) {
        Write-Host ('    ' + (T 'result.ambiguous.reader' @($u.Thumbprint, $u.Reader))) -ForegroundColor White
    }
    Write-Host ''
    Write-Host ('  ' + (T 'result.ambiguous3')) -ForegroundColor Yellow
    Write-Host ''

    Add-Step -Order $script:OrderConnect `
        -Label (T 'fix.rerun.named') `
        -Commands @(('{0} -Thumbprint {1}' -f (Get-SelfInvocation), $usable[0].Thumbprint)) `
        -Note (T 'fix.rerun.named.note')

    Show-CommandBlock
    exit 2
}

$chosen = $usable[0]

$thumbLower = $chosen.Thumbprint.ToLower()
$pageantForCmd = 'pageant.exe'
if ($puttyExe) { $pageantForCmd = Join-Path (Split-Path -Parent $puttyExe) 'pageant.exe' }
$startupDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'

$effUser = $User
$effHost = $ComputerName
$placeholder = $false
if (-not $effUser) { $effUser = 'someone@ad.example.com'; $placeholder = $true }
if (-not $effHost) { $effHost = 'linux-host.ad.example.com'; $placeholder = $true }

$script:LaunchUser = $effUser
$script:LaunchHost = $effHost
$script:LaunchPort = $Port

$puttyForCmd = $puttyExe
if (-not $puttyForCmd) { $puttyForCmd = 'putty.exe' }
$plinkForCmd = 'plink.exe'
if ($cac -and $cac.PlinkPath) { $plinkForCmd = $cac.PlinkPath }

$portArgs = ''
if ($Port -ne 22) { $portArgs = ' -P {0}' -f $Port }

# -A enables agent forwarding, which is what lets sudo on the far end verify a
# signature from this agent. "plink --help" documents it as
# "-A -a     enable / disable agent forwarding"; -A, -a, -agent and -noagent
# were all probed and accepted by this build.
$agentArgs = ''
if ($ForwardAgent) { $agentArgs = ' -A' }

# -x509off is not optional. With X.509 mode left on, PuTTY-CAC offers
# x509v3-ssh-rsa (RFC 6187); OpenSSH does not implement it and answers
# "unsupported public key algorithm", which the client reports only as
# "Server refused our key". The setting is global and shared with Pageant, so
# it is passed explicitly on every invocation.
# -l is used rather than user@host because an AD UPN contains '@'.
$interactive = '{0} -x509off{1} -i CAPI:{2} -l {3}{4} {5}' -f `
    (Format-Exe $puttyForCmd), $agentArgs, $chosen.Thumbprint, $effUser, $portArgs, $effHost

$scripted = '{0} -x509off{1} -batch -i CAPI:{2} -l {3}{4} {5}' -f `
    (Format-Exe $plinkForCmd), $agentArgs, $chosen.Thumbprint, $effUser, $portArgs, $effHost

$script:ChosenThumbprint = $chosen.Thumbprint
$script:LaunchPageantExe = $pageantForCmd

# Steps that need the chosen thumbprint are added here, where it is known, and
# only when the machine is not already set up that way.
$script:StartupLnk = Join-Path $startupDir 'Pageant.lnk'
$startupArgs = 'CAPI:' + $thumbLower
$script:StartupArgs = $startupArgs

$startupOk = $false
try {
    if (Test-Path -LiteralPath $script:StartupLnk) {
        $probe = (New-Object -ComObject WScript.Shell).CreateShortcut($script:StartupLnk)
        $startupOk = ($probe.Arguments.Trim() -ieq $startupArgs)
    }
} catch {
    Write-Verbose 'could not inspect the existing Startup shortcut'
}

if (-not $startupOk) {
    Add-Step -Order $script:OrderPreload `
        -Label (T 'fix.startup.shortcut') `
        -Note (T 'fix.startup.shortcut.note') `
        -Commands @((Get-ShortcutOneLiner -ShortcutPath $script:StartupLnk -Target $pageantForCmd -Arguments $startupArgs)) `
        -Apply {
            Set-StartupShortcutChecked -ShortcutPath $script:StartupLnk `
                -Target $script:LaunchPageantExe -Arguments $script:StartupArgs
        }
}

if ($Launch) {
    Write-Host ('  ' + (T 'result.allpass.launch')) -ForegroundColor Green
} else {
    Write-Host ('  ' + (T 'result.allpass')) -ForegroundColor Green
}
Write-Host ''
Write-Host ('  ' + (T 'result.interactive')) -ForegroundColor White
Write-Host ('    {0}' -f $interactive) -ForegroundColor Green
Write-Host ''
Write-Host ('  ' + (T 'result.scripted')) -ForegroundColor White
Write-Host ('    {0}' -f $scripted) -ForegroundColor Green
Write-Host ''

if ($placeholder) {
    Write-Host ('  ' + (T 'result.placeholder1')) -ForegroundColor Yellow
    Write-Host ('  ' + (T 'result.placeholder2')) -ForegroundColor Yellow
    Write-Host '    -User someone@ad.example.com -ComputerName linux-host.ad.example.com' -ForegroundColor Yellow
    Write-Host ''
}

Write-Host '  Why each part is there:' -ForegroundColor White
Write-Host '    -x509off     turn off X.509 (RFC 6187) mode. Without it PuTTY-CAC offers' -ForegroundColor Gray
Write-Host '                 x509v3-ssh-rsa, OpenSSH refuses with "unsupported public key' -ForegroundColor Gray
Write-Host '                 algorithm", and all you see is "Server refused our key".' -ForegroundColor Gray
Write-Host '                 The setting is global and shared with Pageant, so pass it' -ForegroundColor Gray
Write-Host '                 every time.' -ForegroundColor Gray
Write-Host '    -i CAPI:...  the certificate, by SHA-1 thumbprint, taken from the card and' -ForegroundColor Gray
Write-Host '                 confirmed against the key container actually on the card.' -ForegroundColor Gray
Write-Host '    -l           the login name. AD names contain "@", which user@host parsing' -ForegroundColor Gray
Write-Host '                 would split on, so the name goes in its own argument.' -ForegroundColor Gray
if ($ForwardAgent) {
    Write-Host '    -A           forward the SSH agent, so that sudo on the far end can' -ForegroundColor Gray
    Write-Host '                 verify a signature from the card via pam_ssh_agent_auth.' -ForegroundColor Gray
}
Write-Host ''

if ($ForwardAgent) {
    Write-Host '  SECURITY COST OF -A, which is real and not boilerplate:' -ForegroundColor Yellow
    Write-Host '    While this session is alive, anyone with root on that server can use' -ForegroundColor Yellow
    Write-Host '    the forwarded agent to authenticate AS YOU to other hosts. The agent' -ForegroundColor Yellow
    Write-Host '    signs whatever it is asked to sign, and root on the far end can reach' -ForegroundColor Yellow
    Write-Host '    the forwarded socket. It cannot extract the key -- that stays on the' -ForegroundColor Yellow
    Write-Host '    card -- but it does not need to.' -ForegroundColor Yellow
    Write-Host '    Enable it per session, for hosts you trust with your identity. Never' -ForegroundColor Yellow
    Write-Host '    as "Host *" in a config, and not by default on jump hosts.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  To confirm it worked, in the session:' -ForegroundColor White
    Write-Host '    ssh-add -l          # must list the same fingerprint the server accepts' -ForegroundColor Gray
    Write-Host '    sudo -k && sudo -l  # no password prompt at all means the module' -ForegroundColor Gray
    Write-Host '                        # authenticated: "sufficient" short-circuits the' -ForegroundColor Gray
    Write-Host '                        # stack before pam_unix is ever reached.' -ForegroundColor Gray
    Write-Host ''
    Write-Host '  If sudo still prompts, two measured red herrings to skip:' -ForegroundColor White
    Write-Host '    "ssh-agent socket has incorrect permissions for owner" is usually a' -ForegroundColor Gray
    Write-Host '    malformed SSH_AUTH_SOCK, not the socket mode. Mode 0755 as sshd creates' -ForegroundColor Gray
    Write-Host '    it is fine. Do not chmod the socket -- run "printenv SSH_AUTH_SOCK" and' -ForegroundColor Gray
    Write-Host '    then "ls -l" on exactly that path.' -ForegroundColor Gray
    Write-Host '    "Using default file=/etc/security/authorized_keys" appears even when' -ForegroundColor Gray
    Write-Host '    authorized_keys_command IS in use. It reports the file field default' -ForegroundColor Gray
    Write-Host '    regardless of the key source. It is not the problem.' -ForegroundColor Gray
    Write-Host ''
}
# Preloading setup, parameterised by the thumbprint just discovered from the
# card. Printed only; the script applies none of it. Pageant stores the list in
# lowercase hex, so the commands use that form -- PuTTY-CAC's own saved value
# and the upstream README example differ in case, which is nothing to worry
# about, but matching what Pageant writes keeps the list from gaining a
# duplicate entry.

Write-Host '  To have Pageant come up at logon with just this certificate loaded,' -ForegroundColor White
Write-Host '  so that no "Add CAPI Cert" is needed before each session:' -ForegroundColor White
Write-Host ''
Write-Host '    1. Stop the store being enumerated (this is the important one):' -ForegroundColor Gray
Write-Host '       reg add "HKCU\Software\SimonTatham\PuTTY" /v AutoloadCerts /t REG_DWORD /d 0 /f' -ForegroundColor Cyan
Write-Host ('       (or run: {0} -autoloadoff)' -f (Format-Exe $pageantForCmd)) -ForegroundColor DarkGray
Write-Host ''
Write-Host '    2. Load this one certificate. Passing it to an already-running' -ForegroundColor Gray
Write-Host '       Pageant adds it to that agent rather than starting a second one:' -ForegroundColor Gray
Write-Host ('       {0} CAPI:{1}' -f (Format-Exe $pageantForCmd), $thumbLower) -ForegroundColor Cyan
Write-Host ''
Write-Host '    3. Make it happen at logon, via a Startup shortcut whose Arguments' -ForegroundColor Gray
Write-Host '       are the CAPI: thumbprint (one line, so it pastes as a unit):' -ForegroundColor Gray
Write-Host ('       {0}' -f (Get-ShortcutOneLiner -ShortcutPath (Join-Path $startupDir 'Pageant.lnk') -Target $pageantForCmd -Arguments ('CAPI:' + $thumbLower))) -ForegroundColor Cyan
Write-Host ''
Write-Host '    None of the above is applied by this script. Run it yourself.' -ForegroundColor DarkGray
Write-Host '    Afterwards SaveCertList should stay at one entry across restarts,' -ForegroundColor DarkGray
Write-Host '    and "ssh-add -l" in a forwarded session should show exactly one key.' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  Not recommended by default: -forcepincache. It keeps the card PIN in the' -ForegroundColor Gray
Write-Host '  agent''s memory, so every later signature -- each SSH login, each sudo over' -ForegroundColor Gray
Write-Host '  the forwarded agent -- goes through with no prompt. Convenient for a demo,' -ForegroundColor Gray
Write-Host '  and it stops the card being a second factor for anyone who reaches an' -ForegroundColor Gray
Write-Host '  unlocked session. Decide deliberately, not by accident.' -ForegroundColor Gray
Write-Host ''

# Placed after the -forcepincache note so the explanation can refer back to it
# rather than repeat it. Answers "shouldn't sudo force a PIN prompt?", which is
# the first thing anyone arriving from FIDO asks.
$chosenFamily = 'Unknown'
$chosenToken = @($tokens | Where-Object { $_.Reader -eq $chosen.Reader }) | Select-Object -First 1
if ($chosenToken) { $chosenFamily = $chosenToken.Family }
Show-PinPolicy -Thumbprint $chosen.Thumbprint -Family $chosenFamily

Write-Host '  The server needs nothing copied to it: SSSD derives the SSH public key from' -ForegroundColor Gray
Write-Host '  the certificate and sshd fetches it through' -ForegroundColor Gray
Write-Host '  AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys, so revoking the' -ForegroundColor Gray
Write-Host '  certificate revokes SSH access too.' -ForegroundColor Gray
Write-Host ''

# The consolidated list, last, because that is where a reader looks for "what
# do I actually run". Everything above is explanation; this is the to-do list.
Show-CommandBlock -Thumbprint $chosen.Thumbprint `
    -ConnectLabel (T 'block.connect') -ConnectCommands @($interactive)

if ($Launch) {
    # Refuse to connect to the documentation's example host. Without -User and
    # -ComputerName the emitted command carries placeholders, and "apply and
    # connect" against ad.example.com is not a useful thing to do by accident.
    if ($placeholder) {
        Write-Section (T 'sec.applying')
        Write-Host ('  ' + (T 'launch.needuserhost1')) -ForegroundColor Red
        Write-Host ('  ' + (T 'launch.needuserhost2')) -ForegroundColor Red
        Write-Host ('  ' + (T 'launch.nothingchanged')) -ForegroundColor Red
        Write-Host ''
        exit 8
    }
    exit (Invoke-Launch -ConnectCommand $interactive -PuttyExe $puttyForCmd)
}

exit 0
