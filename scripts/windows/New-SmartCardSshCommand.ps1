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
    [string] $SessionName
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# --------------------------------------------------------------------------
# Reporting helpers
# --------------------------------------------------------------------------

$script:Findings = @()

function Write-Finding {
    param(
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')] [string] $Status,
        [string] $Check,
        [string] $Detail,
        [string] $Remedy
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
        $info.HowDetected += 'CAPI: prefix present in the putty.exe image'
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
                $info.ProbeResult = 'rejected (-x509off unknown: stock PuTTY)'
                $info.IsCac = $false
                $info.HowDetected = @('plink rejected -x509off as an unknown option')
            } elseif ($probe.Text -match 'no valid host name|no hostname|host name') {
                $info.ProbeResult = 'accepted (-x509off is a known option)'
                $info.IsCac = $true
                if ($info.HowDetected -notcontains 'plink accepted -x509off') {
                    $info.HowDetected += 'plink accepted -x509off'
                }
            } else {
                $info.ProbeResult = 'inconclusive'
            }
        } else {
            $info.ProbeResult = 'could not run plink.exe'
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

    $currentReader = $null
    $currentCard = $null
    $pendingContainer = $null
    $pendingSubject = $null

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
        if ($line -match 'Key Container\s*=\s*([0-9a-fA-F-]{36})') {
            $pendingContainer = $Matches[1].ToLower(); continue
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
        Available    = $true
        Readers      = @($readers)
        Certificates = @($unique)
        Raw          = $run.Text
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
        if ($line -match 'Key Container\s*=\s*([0-9a-fA-F-]{36})') {
            $guid = $Matches[1].ToLower()
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
    if ($run.Text -match 'Key Container\s*=\s*([0-9a-fA-F-]{36})') {
        $result.Container = $Matches[1].ToLower()
    }
    # "Missing stored keyset" is certutil's own wording and came back in English
    # even under a localised console; the container comparison below does not
    # depend on it, it is a corroborating signal only.
    if ($run.Text -match 'Missing stored keyset') { $result.MissingKeyset = $true }
    if ($run.Text -match 'Provider\s*=\s*(\S.*?)\s*$') { $result.Provider = $Matches[1] }

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
        return [pscustomobject]@{ Family = 'Unknown'; Display = 'PIV token (vendor not recognised)' }
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
    return [pscustomobject]@{ Family = 'Unknown'; Display = 'PIV token (vendor not recognised)' }
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
    if (-not $Inf) { return 'unknown' }
    if ($Inf -match '^msclmd\.inf$') { return 'Windows inbox PIV minidriver (msclmd.inf)' }
    if ($Inf -match '^scunknown\.inf$') { return 'no minidriver bound (scunknown.inf)' }
    if ($Inf -match '^oem\d+\.inf$') { return ('vendor minidriver ({0})' -f $Inf) }
    return ('minidriver {0}' -f $Inf)
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

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

Write-Host ''
Write-Host 'Smart card SSH readiness check (PuTTY-CAC)' -ForegroundColor White
Write-Host '------------------------------------------' -ForegroundColor DarkGray
Write-Host ('PowerShell {0} on {1}' -f $PSVersionTable.PSVersion, [System.Environment]::OSVersion.VersionString) -ForegroundColor Gray
Write-Host 'Read-only: nothing is launched, downloaded, installed or modified.' -ForegroundColor Gray
Write-Host 'No private key is read and no PIN is requested, stored or logged.' -ForegroundColor Gray
Write-Host 'The checks need no administrator rights; only the suggested' -ForegroundColor Gray
Write-Host 'remedies (installing a minidriver) do.' -ForegroundColor Gray

# ---- 1. dependencies -----------------------------------------------------

Write-Section 'Dependencies'

$puttyExe = Find-Putty -Override $PuttyPath
$cac = $null

if (-not $puttyExe) {
    Write-Finding -Status 'FAIL' -Check 'PuTTY-CAC present' `
        -Detail 'no putty.exe found in the usual install locations or on PATH' `
        -Remedy 'install PuTTY-CAC: winget install --id NoMoreFood.PuTTY-CAC (releases: https://github.com/NoMoreFood/putty-cac/releases)'
} else {
    $cac = Test-PuttyCac -PuttyExe $puttyExe
    $detail = '{0}  [version: {1}]' -f $puttyExe, $cac.FileVersion
    if ($cac.IsCac) {
        Write-Finding -Status 'PASS' -Check 'PuTTY-CAC present' -Detail $detail
        Write-Host ('         detected via: {0}' -f ($cac.HowDetected -join '; ')) -ForegroundColor DarkGray
        Write-Host ('         plink -x509off probe: {0}' -f $cac.ProbeResult) -ForegroundColor DarkGray
        Write-Host ('         CAPI: {0}   PKCS: {1}   x509off: {2}' -f $cac.HasCapi, $cac.HasPkcs, $cac.HasX509Off) -ForegroundColor DarkGray
    } else {
        Write-Finding -Status 'FAIL' -Check 'PuTTY-CAC present' `
            -Detail ('this looks like stock PuTTY, which has no CAPI: support -- {0}' -f $detail) `
            -Remedy 'install PuTTY-CAC: winget install --id NoMoreFood.PuTTY-CAC   (or pass -PuttyPath to point at an existing PuTTY-CAC install)'
        Write-Host ('         plink -x509off probe: {0}' -f $cac.ProbeResult) -ForegroundColor DarkGray
    }
}

$opensc = Find-OpenSC
if ($opensc.Pkcs11Tool -and $opensc.OpenScTool) {
    Write-Finding -Status 'PASS' -Check 'OpenSC present (optional)' `
        -Detail ('pkcs11-tool.exe and opensc-tool.exe found under {0}' -f (Split-Path -Parent $opensc.Pkcs11Tool))
} elseif ($opensc.Pkcs11Tool -or $opensc.OpenScTool) {
    Write-Finding -Status 'WARN' -Check 'OpenSC present (optional)' `
        -Detail 'only part of the OpenSC toolset was found' `
        -Remedy 'winget install --id OpenSC.OpenSC   (only needed to read the thumbprint straight off the card)'
} else {
    Write-Finding -Status 'WARN' -Check 'OpenSC present (optional)' `
        -Detail 'pkcs11-tool.exe / opensc-tool.exe not found' `
        -Remedy 'winget install --id OpenSC.OpenSC   (only needed to read the thumbprint straight off the card; certutil can usually do it alone)'
}

if ($ForwardAgent -or $SessionName) {

    # --- Pageant itself ---
    $pageant = Test-PageantRunning
    if ($pageant.Serving) {
        Write-Finding -Status 'PASS' -Check 'Pageant is running and serving' `
            -Detail ('{0}  [{1}]' -f $pageant.PipeMasked, $pageant.HowDetected)
        if ($pageant.ProcessPath) {
            Write-Host ('         process: {0}' -f $pageant.ProcessPath) -ForegroundColor DarkGray
        }
    } else {
        $pageantExe = 'pageant.exe'
        if ($puttyExe) { $pageantExe = Join-Path (Split-Path -Parent $puttyExe) 'pageant.exe' }
        Write-Finding -Status 'FAIL' -Check 'Pageant is running and serving' `
            -Detail $pageant.HowDetected `
            -Remedy ('start Pageant and load the card certificate into it before connecting: "{0}"' -f $pageantExe)
    }

    Write-Host '         Pageant must already be running with the certificate loaded' -ForegroundColor DarkGray
    Write-Host '         AT CONNECT TIME. Adding it to Pageant after the session is up' -ForegroundColor DarkGray
    Write-Host '         does not retrofit agent forwarding onto that session.' -ForegroundColor DarkGray

    # --- per-session agent forwarding ---
    if (-not $SessionName) {
        Write-Finding -Status 'WARN' -Check 'Saved session has agent forwarding enabled' `
            -Detail 'no -SessionName given, so the per-session AgentFwd/TryAgent values cannot be read' `
            -Remedy 'pass -SessionName <saved session> to have them checked, or tick Connection > SSH > Auth > "Allow agent forwarding" in the PuTTY UI'
    } else {
        $sess = Get-PuttySessionAgentSetting -Name $SessionName
        if (-not $sess.Found) {
            $avail = 'none'
            if (@($sess.Available).Count -gt 0) { $avail = (@($sess.Available) -join ', ') }
            Write-Finding -Status 'WARN' -Check 'Saved session has agent forwarding enabled' `
                -Detail ('no saved session named "{0}"; saved sessions are: {1}' -f $SessionName, $avail) `
                -Remedy 'save the session in PuTTY first, or pass -SessionName exactly as PuTTY lists it'
        } else {
            $fwd = $sess.AgentFwd
            $try = $sess.TryAgent
            $fwdText = 'absent (treated as off)'
            if ($null -ne $fwd) { $fwdText = "$fwd" }

            if ($fwd -eq 1 -and $try -eq 1) {
                Write-Finding -Status 'PASS' -Check 'Saved session has agent forwarding enabled' `
                    -Detail ('session "{0}": AgentFwd={1}, TryAgent={2}' -f $sess.KeyName, $fwdText, $try)
            } else {
                $why = @()
                if ($fwd -ne 1) { $why += ('AgentFwd={0} (agent forwarding off)' -f $fwdText) }
                if ($try -ne 1) { $why += ('TryAgent={0} (Pageant not consulted at all)' -f $try) }
                Write-Finding -Status 'FAIL' -Check 'Saved session has agent forwarding enabled' `
                    -Detail ('session "{0}": {1}' -f $sess.KeyName, ($why -join '; ')) `
                    -Remedy 'either tick Connection > SSH > Auth > "Allow agent forwarding" and re-save the session, or set the values directly (commands below)'
                Write-Host ''
                if ($fwd -ne 1) {
                    Write-Host ('         reg add "{0}" /v AgentFwd /t REG_DWORD /d 1 /f' -f $sess.RegPath) -ForegroundColor Cyan
                }
                if ($try -ne 1) {
                    Write-Host ('         reg add "{0}" /v TryAgent /t REG_DWORD /d 1 /f' -f $sess.RegPath) -ForegroundColor Cyan
                }
                Write-Host '         (the script changes nothing itself -- run these yourself if you want them)' -ForegroundColor DarkGray
            }
            Write-Host ('         Note: -A on the command line covers this run regardless of AgentFwd;' ) -ForegroundColor DarkGray
            Write-Host  '         the saved value matters when the session is launched from the UI.' -ForegroundColor DarkGray
        }
    }
}

# The global X.509 switch, reported for information because it is the setting
# -x509off manipulates and it persists between runs.
$x509 = Get-PuttyGlobalX509
if ($null -eq $x509) {
    Write-Host '  [INFO] global AuthX509: not set (PuTTY-CAC default)' -ForegroundColor Gray
} elseif ($x509 -eq 0) {
    Write-Host '  [INFO] global AuthX509 = 0 (X.509 mode off, which is what you want)' -ForegroundColor Gray
} else {
    Write-Host ('  [INFO] global AuthX509 = {0} (X.509 mode ON globally -- -x509off overrides it per run)' -f $x509) -ForegroundColor Yellow
}

$card = Get-CardCertificate

if (-not $card.Available) {
    Write-Finding -Status 'FAIL' -Check 'Reader and card present' `
        -Detail 'certutil -scinfo produced no output' `
        -Remedy 'check that the Smart Card service (SCardSvr) is running and a reader is attached'
} elseif (@($card.Readers).Count -eq 0) {
    Write-Finding -Status 'FAIL' -Check 'Reader and card present' `
        -Detail 'no smart card readers reported' `
        -Remedy 'attach a reader or token, then re-run'
} else {
    Write-Finding -Status 'PASS' -Check 'Reader and card present' `
        -Detail ('{0} reader(s): {1}' -f @($card.Readers).Count, (@($card.Readers) -join ', '))
}

# ---- 2. tokens -----------------------------------------------------------

Write-Section 'Tokens'

$minidrivers = Get-BoundMinidriver
if ($null -eq $minidrivers) {
    Write-Host '  Bound minidriver: unknown (Get-PnpDevice unavailable on this host)' -ForegroundColor Yellow
} elseif (@($minidrivers).Count -eq 0) {
    Write-Host '  Bound minidriver: none reported for a present card' -ForegroundColor Yellow
} else {
    foreach ($m in $minidrivers) {
        $label = [string] $m.FriendlyName
        if ($label.Length -gt 44) { $label = $label.Substring(0, 41) + '...' }
        Write-Host ('  {0,-46} {1}' -f $label, $m.Kind) -ForegroundColor Gray
    }
}

$readerList = @($card.Readers)
if ($Reader) {
    $narrowed = @($readerList | Where-Object { $_ -like ('*' + $Reader + '*') })
    if (@($narrowed).Count -gt 0) {
        $readerList = $narrowed
    } else {
        Write-Host ''
        Write-Host ('  No reader name contains "{0}"; showing all readers.' -f $Reader) -ForegroundColor Yellow
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
    }
}

if (@($tokens).Count -eq 0) {
    Write-Host '  No tokens to classify.' -ForegroundColor Yellow
} else {
    Write-Host ''
    foreach ($t in $tokens) {
        Write-Host ('  {0,-46} {1}' -f $t.Reader, $t.Display) -ForegroundColor Gray
    }
    if (@($tokens).Count -gt 1) {
        Write-Host ''
        Write-Host ('  {0} tokens are attached at once. The script will not pick one for you.' -f @($tokens).Count) -ForegroundColor Yellow
        Write-Host '  Narrow the choice with -Reader <text> or -Thumbprint <sha1> if the' -ForegroundColor Yellow
        Write-Host '  checks below leave more than one usable certificate.' -ForegroundColor Yellow
    } elseif ($Reader) {
        Write-Host ''
        Write-Host ('  Narrowed to one token by -Reader "{0}".' -f $Reader) -ForegroundColor Gray
    }
}

# ---- 3. certificates -----------------------------------------------------

Write-Section 'Card certificates and key containers'

$cardContainers = @{}
if ($card.Available) { $cardContainers = Get-CardContainer -RawScInfo $card.Raw }

$candidates = @($card.Certificates)

if ($UseOpenSC) {
    $extra = Get-OpenScCardCertificate -OpenSC $opensc
    foreach ($e in $extra) {
        $known = @($candidates | Where-Object { $_.Thumbprint -eq $e.Thumbprint })
        if (@($known).Count -gt 0) {
            Write-Host ('  OpenSC agrees with certutil on {0} ({1})' -f $e.Thumbprint, $e.Reader) -ForegroundColor DarkGray
        } else {
            Write-Host ('  OpenSC found a certificate certutil did not report: {0} ({1})' -f $e.Thumbprint, $e.Reader) -ForegroundColor Yellow
            $candidates += [pscustomobject]@{
                Thumbprint    = $e.Thumbprint
                Reader        = $e.Reader
                Card          = $null
                CardContainer = $null
                Subject       = $null
                Source        = $e.Source
            }
        }
    }
}

if ($Reader) {
    $candidates = @($candidates | Where-Object { $_.Reader -and $_.Reader -like ('*' + $Reader + '*') })
    Write-Host ('  Filtered to readers matching "{0}": {1} candidate(s)' -f $Reader, @($candidates).Count) -ForegroundColor Gray
}
if ($Thumbprint) {
    $wanted = ($Thumbprint -replace '[^0-9a-fA-F]', '').ToUpper()
    $candidates = @($candidates | Where-Object { $_.Thumbprint -eq $wanted })
    if (@($candidates).Count -eq 0) {
        $candidates = @([pscustomobject]@{
            Thumbprint = $wanted; Reader = '(supplied by -Thumbprint)'; Card = $null
            CardContainer = $null; Subject = $null; Source = '-Thumbprint'
        })
    }
}

$usable = @()

if (@($candidates).Count -eq 0) {
    Write-Finding -Status 'FAIL' -Check 'A usable card certificate was found' `
        -Detail 'no certificate could be read from any card' `
        -Remedy 'the card may not be provisioned, or its minidriver may be missing -- see below'
} else {
    foreach ($c in $candidates) {
        Write-Host ''
        Write-Host ('  Certificate {0}' -f $c.Thumbprint) -ForegroundColor White
        Write-Host ('    reader:         {0}' -f $c.Reader) -ForegroundColor Gray
        Write-Host ('    read from:      {0}' -f $c.Source) -ForegroundColor Gray
        if ($c.CardContainer) {
            Write-Host ('    container on card:  {0}' -f $c.CardContainer) -ForegroundColor Gray
        } else {
            Write-Host '    container on card:  unknown' -ForegroundColor Gray
        }

        $store = Get-StoreKeyContainer -Thumb $c.Thumbprint
        if ($store.Container) {
            Write-Host ('    container in store: {0}' -f $store.Container) -ForegroundColor Gray
        } else {
            Write-Host '    container in store: unknown' -ForegroundColor Gray
        }

        if (-not $store.InStore) {
            Write-Finding -Status 'FAIL' -Check ('{0}: present in the user certificate store' -f $c.Thumbprint) `
                -Detail 'the certificate is on the card but not in Cert:\CurrentUser\My' `
                -Remedy 'CAPI: addressing reads the store, so let Windows register the card certificate (re-insert the token, or use the vendor minidriver tooling), or address the card directly with -i PKCS:<id>=<path-to-pkcs11.dll>'
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
            Write-Finding -Status 'FAIL' -Check ('{0}: key container resolves' -f $c.Thumbprint) `
                -Detail 'certutil reports "Missing stored keyset" -- the store entry names a key container that cannot be opened' `
                -Remedy 'this certificate is unusable; pick another, or delete the stale store entry and re-register the card certificate'
        } elseif (-not $store.Container -or @($onCard).Count -eq 0) {
            Write-Finding -Status 'WARN' -Check ('{0}: key container matches the card' -f $c.Thumbprint) `
                -Detail 'could not read one or both container GUIDs, so the comparison is unknown' `
                -Remedy 'run "certutil -scinfo -silent" and "certutil -silent -user -store My <thumbprint>" by hand and compare the Key Container lines'
        } elseif ($onCard -contains $store.Container) {
            Write-Finding -Status 'PASS' -Check ('{0}: key container matches the card' -f $c.Thumbprint) `
                -Detail ('store and card both name {0}' -f $store.Container)
            $usable += $c
        } else {
            Write-Finding -Status 'FAIL' -Check ('{0}: key container matches the card' -f $c.Thumbprint) `
                -Detail ('store names {0}, but the card holds {1}' -f $store.Container, (@($onCard) -join ', ')) `
                -Remedy 'this store entry belongs to a different (probably older) card; Windows will say the smart card cannot perform the requested operation. Delete the stale entry or pick the certificate whose container is on this card'
        }
    }
}

# A view of the store from the other side, because this is where the mess
# accumulates: entries whose key container no longer exists anywhere.
try {
    $storeAll = @(Get-ChildItem Cert:\CurrentUser\My -ErrorAction Stop)
    if (@($storeAll).Count -gt 0) {
        Write-Host ''
        Write-Host ('  The user certificate store holds {0} entr(y/ies).' -f @($storeAll).Count) -ForegroundColor Gray
        Write-Host '  Stale smart card entries are normal and harmless until one is picked' -ForegroundColor Gray
        Write-Host '  by mistake; always take the thumbprint from the card, as above.' -ForegroundColor Gray
    }
} catch {
    Write-Verbose 'could not enumerate Cert:\CurrentUser\My'
}

# ---- 4. the command ------------------------------------------------------

Write-Section 'Result'

if (@($usable).Count -eq 0) {
    Write-Host '  No usable card certificate, so no command is emitted.' -ForegroundColor Red

    $family = 'Unknown'
    $tokenName = 'unknown token'
    if (@($tokens).Count -eq 1) {
        $family = $tokens[0].Family; $tokenName = $tokens[0].Reader
    } elseif (@($tokens).Count -gt 1) {
        Write-Host ''
        Write-Host '  More than one token is attached, so the advice below is given per token.' -ForegroundColor Yellow
        foreach ($t in $tokens) { Show-MinidriverAdvice -Family $t.Family -TokenName $t.Reader }
        $family = $null
    }
    if ($family) { Show-MinidriverAdvice -Family $family -TokenName $tokenName }

    if ($opensc.Pkcs11Tool -and $opensc.Module -and -not $UseOpenSC) {
        Write-Host ''
        Write-Host '  To read the certificates straight off the card, independently of the' -ForegroundColor Gray
        Write-Host '  Windows store, re-run this script with -UseOpenSC, or by hand:' -ForegroundColor Gray
        Write-Host ('    & "{0}" --module "{1}" --list-token-slots' -f $opensc.Pkcs11Tool, $opensc.Module) -ForegroundColor Gray
    }
    Write-Host ''
    exit 1
}

if (@($usable).Count -gt 1) {
    Write-Host ('  {0} usable certificates were found. Choose one -- the script will not' -f @($usable).Count) -ForegroundColor Yellow
    Write-Host '  choose for you:' -ForegroundColor Yellow
    Write-Host ''
    foreach ($u in $usable) {
        Write-Host ('    -Thumbprint {0}    (reader: {1})' -f $u.Thumbprint, $u.Reader) -ForegroundColor White
    }
    Write-Host ''
    Write-Host '  Re-run with -Thumbprint <sha1>, or -Reader <text> to narrow by reader.' -ForegroundColor Yellow
    Write-Host ''
    exit 2
}

$chosen = $usable[0]

$effUser = $User
$effHost = $ComputerName
$placeholder = $false
if (-not $effUser) { $effUser = 'someone@ad.example.com'; $placeholder = $true }
if (-not $effHost) { $effHost = 'linux-host.ad.example.com'; $placeholder = $true }

$puttyForCmd = $puttyExe
if (-not $puttyForCmd) { $puttyForCmd = 'putty.exe' }
$plinkForCmd = 'plink.exe'
if ($cac -and $cac.PlinkPath) { $plinkForCmd = $cac.PlinkPath }

function Format-Exe { param([string] $Path) if ($Path -match '\s') { return '"' + $Path + '"' } return $Path }

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

Write-Host '  All checks passed. Run this yourself -- the script does not launch it.' -ForegroundColor Green
Write-Host ''
Write-Host '  Interactive (PuTTY window):' -ForegroundColor White
Write-Host ('    {0}' -f $interactive) -ForegroundColor Green
Write-Host ''
Write-Host '  Scripted / batch (plink, no interactive prompts):' -ForegroundColor White
Write-Host ('    {0}' -f $scripted) -ForegroundColor Green
Write-Host ''

if ($placeholder) {
    Write-Host '  NOTE: -User and/or -ComputerName were not given, so the command above' -ForegroundColor Yellow
    Write-Host '  contains example values. Re-run with your own, e.g.' -ForegroundColor Yellow
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
Write-Host '  The server needs nothing copied to it: SSSD derives the SSH public key from' -ForegroundColor Gray
Write-Host '  the certificate and sshd fetches it through' -ForegroundColor Gray
Write-Host '  AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys, so revoking the' -ForegroundColor Gray
Write-Host '  certificate revokes SSH access too.' -ForegroundColor Gray
Write-Host ''

exit 0
