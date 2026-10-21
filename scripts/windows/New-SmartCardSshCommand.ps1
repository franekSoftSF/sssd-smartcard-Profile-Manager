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
    [switch] $Launch
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# --------------------------------------------------------------------------
# Reporting helpers
# --------------------------------------------------------------------------

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

    Write-Section 'Commands to run on this workstation'

    $steps = @($script:Steps | Sort-Object Order, Seq)

    if (@($steps).Count -eq 0 -and @($ConnectCommands).Count -gt 0) {
        Write-Host '  Every check passed: there is nothing to fix on this workstation.' -ForegroundColor Green
    } else {
        Write-Host '  Nothing below has been applied. Copy and run these yourself, in order.' -ForegroundColor Gray
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
            Write-Host '       (these lines are one unit -- paste them in together)' -ForegroundColor DarkGray
        } elseif (@($cmds).Count -gt 1) {
            Write-Host '       (separate commands; run them in this order)' -ForegroundColor DarkGray
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
        if (-not $label) { $label = 'Connect' }
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

    Write-Section 'Applying (-Launch)'

    $steps = @($script:Steps | Sort-Object Order, Seq)
    $installs = @($steps | Where-Object { $_.IsInstall })

    if (@($installs).Count -gt 0) {
        Write-Host '  Stopping before any change: something has to be installed first.' -ForegroundColor Red
        Write-Host '  -Launch configures what is already on this machine; it does not install' -ForegroundColor Yellow
        Write-Host '  software, because that downloads, usually needs elevation, and changes' -ForegroundColor Yellow
        Write-Host '  the machine rather than your configuration.' -ForegroundColor Yellow
        Write-Host ''
        foreach ($s in $installs) {
            Write-Host ('    {0}' -f $s.Label) -ForegroundColor White
            foreach ($c in @($s.Commands)) { Write-Host ('      {0}' -f $c) -ForegroundColor Cyan }
            if ($s.Note) { Write-Host ('      {0}' -f $s.Note) -ForegroundColor Gray }
        }
        Write-Host ''
        Write-Host '  Install the above, then re-run. NOTHING HAS BEEN CHANGED.' -ForegroundColor Red
        Write-Host ''
        return 3
    }

    $actionable = @($steps | Where-Object { -not $_.IsInstall })
    $failed = 0

    if (@($actionable).Count -eq 0) {
        Write-Host '  Nothing to apply: this workstation is already configured.' -ForegroundColor Green
    }

    foreach ($s in $actionable) {
        if (-not $s.Apply) {
            Write-Host ('  [SKIP] {0}' -f $s.Label) -ForegroundColor Yellow
            Write-Host '         Cannot be applied automatically -- it needs a decision or a' -ForegroundColor Gray
            Write-Host '         file this script will not invent. Run it yourself:' -ForegroundColor Gray
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
            Write-Host ('  [FAIL] {0}' -f $s.Label) -ForegroundColor Red
            Write-Host ('         {0}' -f $_.Exception.Message) -ForegroundColor Red
            $failed++
            continue
        }

        if ($result -and $result.Ok) {
            Write-Host ('  [DONE] {0}' -f $s.Label) -ForegroundColor Green
            $undo = @()
            if ($result.PSObject.Properties.Name -contains 'Undo') { $undo = @($result.Undo) }
            if (@($undo).Count -eq 0) { $undo = @($s.Undo) }
            Add-ChangeRecord -What $s.Label -Undo $undo
            foreach ($u in $undo) {
                Write-Host ('         undo: {0}' -f $u) -ForegroundColor DarkGray
            }
        } else {
            $msg = 'no result returned'
            if ($result -and $result.PSObject.Properties.Name -contains 'Error' -and $result.Error) { $msg = $result.Error }
            Write-Host ('  [FAIL] {0}' -f $s.Label) -ForegroundColor Red
            Write-Host ('         {0}' -f $msg) -ForegroundColor Red
            Write-Host '         If this says access is denied, it needs rights the checks do not' -ForegroundColor Gray
            Write-Host '         assume. Nothing is retried with elevation.' -ForegroundColor Gray
            $failed++
        }
    }

    Write-Host ''
    Show-AppliedSummary

    if ($failed -gt 0) {
        Write-Host ('  {0} step(s) did not complete, so no connection is started.' -f $failed) -ForegroundColor Red
        Write-Host '  Fix those and re-run, or run the printed commands yourself.' -ForegroundColor Yellow
        Write-Host ''
        return 4
    }

    # Re-check: read the state back rather than assume the writes took.
    Write-Host '  Re-checking the applied state by reading it back...' -ForegroundColor White
    $recheck = Test-LaunchPreconditions
    foreach ($line in $recheck.Lines) {
        Write-Host ('    {0}' -f $line) -ForegroundColor Gray
    }
    if (-not $recheck.Ok) {
        Write-Host ''
        Write-Host '  The re-check did not pass, so no connection is started.' -ForegroundColor Red
        Write-Host ''
        return 5
    }
    Write-Host '  Re-check passed.' -ForegroundColor Green
    Write-Host ''

    if (-not $PuttyExe -or -not (Test-Path -LiteralPath $PuttyExe)) {
        Write-Host '  PuTTY was not found, so there is nothing to start.' -ForegroundColor Red
        return 6
    }

    Write-Host ('  Starting: {0}' -f $ConnectCommand) -ForegroundColor Green
    Write-Host '  PuTTY will ask for the card PIN. This script never sees it.' -ForegroundColor Gray
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
        Write-Host ('  Could not start PuTTY: {0}' -f $_.Exception.Message) -ForegroundColor Red
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
        $lines += 'AuthX509 = 0 or unset (X.509 mode off): ok'
    } else {
        $lines += ('AuthX509 = {0}: still on' -f $x); $ok = $false
    }

    $pre = Get-PageantPreloadConfig
    if ($pre.AutoloadCerts -eq 1) {
        $lines += 'AutoloadCerts = 1: still enumerating the whole store'; $ok = $false
    } else {
        $lines += 'AutoloadCerts = 0 or unset: ok'
    }

    if ($script:LaunchSessionKey) {
        $s = Get-PuttySessionAgentSetting -Name $script:LaunchSessionKey
        if ($s.Found -and $s.AgentFwd -eq 1 -and $s.TryAgent -eq 1) {
            $lines += ('session "{0}": AgentFwd=1, TryAgent=1: ok' -f $s.KeyName)
        } elseif ($s.Found) {
            $lines += ('session "{0}": AgentFwd={1}, TryAgent={2}: not both 1' -f $s.KeyName, $s.AgentFwd, $s.TryAgent)
            $ok = $false
        }
    }

    if ($script:StartupLnk -and (Test-Path -LiteralPath $script:StartupLnk)) {
        try {
            $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($script:StartupLnk)
            if ($sc.Arguments.Trim() -ieq $script:StartupArgs) {
                $lines += 'Startup shortcut arguments match the chosen certificate: ok'
            } else {
                $lines += ('Startup shortcut arguments are "{0}": not the chosen certificate' -f $sc.Arguments.Trim())
                $ok = $false
            }
        } catch {
            $lines += 'Startup shortcut could not be read back'; $ok = $false
        }
    }

    return [pscustomobject]@{ Ok = $ok; Lines = $lines }
}

function Show-AppliedSummary {
    if (@($script:Applied).Count -eq 0) {
        Write-Host '  No changes were made.' -ForegroundColor Gray
        Write-Host ''
        return
    }
    Write-Host ('  {0} change(s) made. To reverse them:' -f @($script:Applied).Count) -ForegroundColor White
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

# Add the vendor minidriver install to the to-do list. Only Yubico has a winget
# package -- verified against the live catalogue, as were the other ids used in
# this script. HID ship no package at all, so that step is a note pointing at
# their documented download location rather than a command that does not exist.
function Add-MinidriverStep {
    param([string] $Family, [string] $TokenName)

    if ($Family -eq 'Yubico') {
        Add-Step -Order $script:OrderInstall `
            -Label 'Install the YubiKey Smart Card Minidriver (for provisioning/management)' `
            -Commands @('winget install --id Yubico.YubiKeySmartCardMinidriver')
    }
    elseif ($Family -eq 'HIDCrescendo') {
        Add-Step -Order $script:OrderInstall `
            -Label 'Install the HID Crescendo Minidriver (no winget package exists)' `
            -Note 'Download it from www.hidglobal.com/drivers -- HID''s own documentation names that as the location, and the portal refuses automated clients, so open it in a browser or ask your HID representative. Install docs: https://docs.hidglobal.com/crescendo-md-v1.3/MiniDriver/install_minidriver.htm'
    }
    else {
        Add-Step -Order $script:OrderInstall `
            -Label ('Find the minidriver for this token: {0}' -f $TokenName) `
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
        -Remedy 'install PuTTY-CAC: winget install --id NoMoreFood.PuTTY-CAC (releases: https://github.com/NoMoreFood/putty-cac/releases)' `
        -FixLabel 'Install PuTTY-CAC (stock PuTTY cannot do CAPI: at all)' `
        -FixOrder $script:OrderInstall -FixIsInstall `
        -Fix @('winget install --id NoMoreFood.PuTTY-CAC')
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
            -Remedy 'install PuTTY-CAC: winget install --id NoMoreFood.PuTTY-CAC   (or pass -PuttyPath to point at an existing PuTTY-CAC install)' `
            -FixLabel 'Install PuTTY-CAC (what is installed is stock PuTTY, which has no CAPI: support)' `
            -FixOrder $script:OrderInstall -FixIsInstall `
            -Fix @('winget install --id NoMoreFood.PuTTY-CAC')
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
            -Remedy ('start Pageant and load the card certificate into it before connecting: "{0}"' -f $pageantExe) `
            -FixLabel 'Start Pageant with the card certificate loaded' `
            -FixOrder $script:OrderAgent `
            -Fix @(('{0} CAPI:<THUMBPRINT>' -f (Format-Exe $pageantExe)))
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
            $script:LaunchSessionKey = $sess.KeyName
            $script:LaunchNeedAgentFwd = ($fwd -ne 1)
            $script:LaunchNeedTryAgent = ($try -ne 1)
            $fwdText = 'absent (treated as off)'
            if ($null -ne $fwd) { $fwdText = "$fwd" }

            if ($fwd -eq 1 -and $try -eq 1) {
                Write-Finding -Status 'PASS' -Check 'Saved session has agent forwarding enabled' `
                    -Detail ('session "{0}": AgentFwd={1}, TryAgent={2}' -f $sess.KeyName, $fwdText, $try)
            } else {
                $why = @()
                if ($fwd -ne 1) { $why += ('AgentFwd={0} (agent forwarding off)' -f $fwdText) }
                if ($try -ne 1) { $why += ('TryAgent={0} (Pageant not consulted at all)' -f $try) }
                # Built as a plain array first. Writing the filter as a pipe
                # inside the @( ... ) argument parses on PowerShell 7 but is
                # "An empty pipe element is not allowed" on 5.1, which is the
                # version this has to work on.
                $sessionFix = @()
                if ($fwd -ne 1) { $sessionFix += ('reg add "{0}" /v AgentFwd /t REG_DWORD /d 1 /f' -f $sess.RegPath) }
                if ($try -ne 1) { $sessionFix += ('reg add "{0}" /v TryAgent /t REG_DWORD /d 1 /f' -f $sess.RegPath) }

                Write-Finding -Status 'FAIL' -Check 'Saved session has agent forwarding enabled' `
                    -Detail ('session "{0}": {1}' -f $sess.KeyName, ($why -join '; ')) `
                    -Remedy 'either tick Connection > SSH > Auth > "Allow agent forwarding" and re-save the session, or set the values directly (commands below)' `
                    -FixLabel ('Enable agent forwarding on the saved session "{0}"' -f $sess.KeyName) `
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
                Write-Host '         (the script changes nothing unless -Launch is given)' -ForegroundColor DarkGray
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

# Pageant's preload configuration. Checked unconditionally, not just under
# -ForwardAgent: whenever Pageant is consulted at all (TryAgent defaults to 1)
# an over-full SaveCertList can exhaust the server's MaxAuthTries before the
# card's key is reached, and that failure reads as "Server refused our key".
$preload = Get-PageantPreloadConfig
if (-not $preload.Readable) {
    Write-Host '  [INFO] Pageant preload configuration: unknown (PuTTY registry key unreadable)' -ForegroundColor Gray
} else {
    $countText = 'not set'
    if ($null -ne $preload.EntryCount) { $countText = '{0} entr(y/ies)' -f $preload.EntryCount }

    if ($preload.AutoloadCerts -eq 1) {
        Write-Finding -Status 'WARN' -Check 'Pageant preloads one certificate, not the whole store' `
            -Detail ('AutoloadCerts = 1: Pageant re-enumerates the ENTIRE Windows certificate store at every start and rewrites SaveCertList (currently {0}), dead key containers included' -f $countText) `
            -Remedy 'set AutoloadCerts = 0 and preload the one certificate instead (commands printed below). Trimming SaveCertList by hand does nothing while this is 1 -- it is rebuilt on the next start' `
            -FixLabel 'Stop Pageant enumerating the whole certificate store (MaxAuthTries)' `
            -FixOrder $script:OrderPreload `
            -Fix @('reg add "HKCU\Software\SimonTatham\PuTTY" /v AutoloadCerts /t REG_DWORD /d 0 /f') `
            -FixApply { Set-RegDwordChecked -SubKey 'Software\SimonTatham\PuTTY' -Name 'AutoloadCerts' -Value 0 }
        Write-Host '         Why it matters: the agent offers keys ONE AT A TIME and OpenSSH''s' -ForegroundColor Yellow
        Write-Host '         default MaxAuthTries is 6. With a full store the card''s key may' -ForegroundColor Yellow
        Write-Host '         never be reached, and you get "Server refused our key" -- the same' -ForegroundColor Yellow
        Write-Host '         message as the X.509 trap and as a stale store entry.' -ForegroundColor Yellow
    } elseif ($null -eq $preload.AutoloadCerts) {
        Write-Host ('  [INFO] Pageant preload: AutoloadCerts not set (default), SaveCertList holds {0}' -f $countText) -ForegroundColor Gray
    } else {
        Write-Finding -Status 'PASS' -Check 'Pageant preloads one certificate, not the whole store' `
            -Detail ('AutoloadCerts = 0, SaveCertList holds {0}' -f $countText)
        if ($null -ne $preload.EntryCount -and $preload.EntryCount -gt 1) {
            Write-Host ('         Note: {0} entries are saved. The store is no longer being' -f $preload.EntryCount) -ForegroundColor Yellow
            Write-Host '         enumerated, so trimming the list will now stick -- and with' -ForegroundColor Yellow
            Write-Host '         MaxAuthTries at 6 it is worth trimming.' -ForegroundColor Yellow
        }
    }
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
} elseif (@($card.ReadersWithCard).Count -eq 0) {
    # A reader is not a card. Counting readers alone reported "card present"
    # on a workstation with both tokens unplugged, which is the kind of green
    # result that sends someone looking at the server.
    Write-Finding -Status 'FAIL' -Check 'Reader and card present' `
        -Detail ('{0} reader(s) attached, none holding a card' -f @($card.Readers).Count) `
        -Remedy 'insert the card or plug the token in, then re-run'
    Write-Host ('         readers: {0}' -f (@($card.Readers) -join ', ')) -ForegroundColor Gray
} else {
    Write-Finding -Status 'PASS' -Check 'Reader and card present' `
        -Detail ('{0} of {1} reader(s) hold a card: {2}' -f `
            @($card.ReadersWithCard).Count, @($card.Readers).Count,
            (@($card.ReadersWithCard) -join ', '))
    $empty = @($card.Readers | Where-Object { @($card.ReadersWithCard) -notcontains $_ })
    if ($empty.Count -gt 0) {
        Write-Host ('         empty: {0}' -f ($empty -join ', ')) -ForegroundColor Gray
    }
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
        HasCard      = (@($card.ReadersWithCard) -contains $r)
    }
}

if (@($tokens).Count -eq 0) {
    Write-Host '  No tokens to classify.' -ForegroundColor Yellow
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
        Write-Host ('  {0} tokens are attached at once. The script will not pick one for you.' -f @($withCards).Count) -ForegroundColor Yellow
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
                CardProvider  = $null
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
            CardContainer = $null; CardProvider = $null; Subject = $null; Source = '-Thumbprint'
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

        # The CSP for -repairstore, taken from what -scinfo actually reported
        # for this card. Falls back to the store's own Provider, then to a
        # placeholder -- never to a guessed provider name, because the wrong
        # CSP makes -repairstore fail in a way that looks like a bad card.
        # Computed after $store is read, since that is one of the sources.
        $csp = $c.CardProvider
        if (-not $csp) { $csp = $store.Provider }
        if (-not $csp) { $csp = '<the Provider that -scinfo names for this card>' }

        if (-not $store.InStore) {
            Write-Finding -Status 'FAIL' -Check ('{0}: present in the user certificate store' -f $c.Thumbprint) `
                -Detail 'the certificate is on the card but not in Cert:\CurrentUser\My' `
                -Remedy 'CAPI: addressing reads the store, so the certificate has to be registered there' `
                -FixLabel ('Re-insert the token, then re-run -- certificate {0} is on the card but not in the store' -f $c.Thumbprint) `
                -FixOrder $script:OrderRegister `
                -FixNote 'The propagation service only registers card certificates on an insertion event, so a certificate written to a card that was already in the reader is never seen. Unplug the token, plug it back in, and run this script again. The two steps that follow are only needed if that does not fix it.'

            # Two genuinely separate commands, run in order, so they are two
            # numbered steps rather than one step with two lines.
            Add-Step -Order $script:OrderRegister `
                -Label ('Only if re-inserting did not work: add certificate {0} to the store' -f $c.Thumbprint) `
                -Note 'Read the certificate off the card first -- see -UseOpenSC, which prints the pkcs11-tool command that writes it to a .der file.' `
                -Commands @('certutil -user -addstore My <cert.der>')
            Add-Step -Order $script:OrderRegister `
                -Label ('Only if re-inserting did not work: bind {0} to the key on the card' -f $c.Thumbprint) `
                -Note '"Encryption test passed" in the output means the binding took. The CSP below is the one -scinfo reported for this card; a wrong CSP fails in a way that looks like a bad card.' `
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
            Write-Finding -Status 'FAIL' -Check ('{0}: key container resolves' -f $c.Thumbprint) `
                -Detail 'certutil reports "Missing stored keyset" -- the store entry names a key container that cannot be opened' `
                -Remedy 'this certificate is unusable; pick another, or delete the stale store entry and re-register the card certificate' `
                -FixLabel ('Re-bind store entry {0} to the key on the card' -f $c.Thumbprint) `
                -FixOrder $script:OrderRegister `
                -FixNote '"Encryption test passed" in the output means the binding took. If it still fails the certificate belongs to a card that is not here -- pick another, or delete the entry with "certutil -user -delstore My <thumbprint>".' `
                -Fix @(('certutil -user -csp "{0}" -repairstore My {1}' -f $csp, $c.Thumbprint))
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

    # With no certificate to work from, the minidriver and OpenSC installs are
    # the steps that might actually produce one, so they join the list here
    # rather than at their own checks -- where they would be noise on a machine
    # whose card reads fine.
    foreach ($t in $tokens) { Add-MinidriverStep -Family $t.Family -TokenName $t.Reader }
    if (-not ($opensc.Pkcs11Tool -and $opensc.OpenScTool)) {
        Add-Step -Order $script:OrderInstall `
            -Label 'Install OpenSC, to read the certificate off the card' `
            -Commands @('winget install --id OpenSC.OpenSC')
    }

    if ($opensc.Pkcs11Tool -and $opensc.Module -and -not $UseOpenSC) {
        Write-Host ''
        Write-Host '  To read the certificates straight off the card, independently of the' -ForegroundColor Gray
        Write-Host '  Windows store, re-run this script with -UseOpenSC, or by hand:' -ForegroundColor Gray
        Write-Host ('    & "{0}" --module "{1}" --list-token-slots' -f $opensc.Pkcs11Tool, $opensc.Module) -ForegroundColor Gray
    }

    Add-Step -Order $script:OrderConnect `
        -Label 'Re-run this script once the steps above are done' `
        -Commands @((Get-SelfInvocation))

    Show-CommandBlock
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

    Add-Step -Order $script:OrderConnect `
        -Label 'Re-run naming the certificate you want' `
        -Commands @(('{0} -Thumbprint {1}' -f (Get-SelfInvocation), $usable[0].Thumbprint)) `
        -Note 'The thumbprint above is the first of the usable certificates listed; substitute whichever one you mean.'

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
        -Label 'Load the certificate into Pageant at every logon' `
        -Note 'One line, so it pastes as a single unit. Replaces any existing Pageant shortcut in Startup; -Launch keeps a .bak of the old one.' `
        -Commands @((Get-ShortcutOneLiner -ShortcutPath $script:StartupLnk -Target $pageantForCmd -Arguments $startupArgs)) `
        -Apply {
            Set-StartupShortcutChecked -ShortcutPath $script:StartupLnk `
                -Target $script:LaunchPageantExe -Arguments $script:StartupArgs
        }
}

if ($Launch) {
    Write-Host '  All checks passed. -Launch will apply what is needed and then connect.' -ForegroundColor Green
} else {
    Write-Host '  All checks passed. Run this yourself -- the script does not launch it.' -ForegroundColor Green
}
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

Write-Host '  The server needs nothing copied to it: SSSD derives the SSH public key from' -ForegroundColor Gray
Write-Host '  the certificate and sshd fetches it through' -ForegroundColor Gray
Write-Host '  AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys, so revoking the' -ForegroundColor Gray
Write-Host '  certificate revokes SSH access too.' -ForegroundColor Gray
Write-Host ''

# The consolidated list, last, because that is where a reader looks for "what
# do I actually run". Everything above is explanation; this is the to-do list.
Show-CommandBlock -Thumbprint $chosen.Thumbprint `
    -ConnectLabel 'Connect' -ConnectCommands @($interactive)

if ($Launch) {
    # Refuse to connect to the documentation's example host. Without -User and
    # -ComputerName the emitted command carries placeholders, and "apply and
    # connect" against ad.example.com is not a useful thing to do by accident.
    if ($placeholder) {
        Write-Section 'Applying (-Launch)'
        Write-Host '  -Launch needs -User and -ComputerName: the command above still' -ForegroundColor Red
        Write-Host '  contains example values, and connecting to those would be pointless.' -ForegroundColor Red
        Write-Host '  NOTHING HAS BEEN CHANGED.' -ForegroundColor Red
        Write-Host ''
        exit 8
    }
    exit (Invoke-Launch -ConnectCommand $interactive -PuttyExe $puttyForCmd)
}

exit 0
