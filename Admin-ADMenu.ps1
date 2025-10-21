# Requires: RSAT Active Directory module (ActiveDirectory)
# Run in Windows PowerShell as a domain admin.

# --- Safety toggle (set $WhatIf to $true for dry-run) ---
$WhatIf = $false

function Ensure-ADModule {
    if (-not (Get-Module -ListAvailable ActiveDirectory)) {
        Write-Error "ActiveDirectory module not found. Install RSAT or run on a DC."
        throw
    }
    Import-Module ActiveDirectory -ErrorAction Stop
}

function Pause-Enter { Read-Host -Prompt "Press ENTER to continue..." | Out-Null }

function Confirm-Action($Message) {
    $ans = Read-Host "$Message [y/N]"
    return ($ans -match '^(y|yes)$')
}

# --- Helpers: identity lookups ---
function Get-UserBySamOrUPN($id) {
    try { Get-ADUser -Identity $id -ErrorAction Stop }
    catch { Get-ADUser -LDAPFilter "(|(sAMAccountName=$id)(userPrincipalName=$id))" -ErrorAction Stop }
}
function Get-GroupBySamOrCN($id) {
    try { Get-ADGroup -Identity $id -ErrorAction Stop }
    catch { Get-ADGroup -LDAPFilter "(|(sAMAccountName=$id)(cn=$id))" -ErrorAction Stop }
}

# --- Logon Hours helper (21 bytes; bit=hour) ---
# Build Mon–Sun (0–6) with allowed hour ranges (0-23).
function New-LogonHoursBytes([hashtable]$Schedule) {
    # Each day has 24 bits, packed into 3 bytes; 7 * 3 = 21 bytes total.
    $bytes = New-Object 'System.Byte[]' 21
    for ($day=0; $day -le 6; $day++) {
        $hours = 0..23 | ForEach-Object { $false }
        if ($Schedule.ContainsKey($day)) {
            foreach ($range in $Schedule[$day]) {
                $start = $range[0]; $end = $range[1]
                for ($h=$start; $h -lt $end; $h++) { $hours[$h] = $true }
            }
        }
        # Pack 24 bits (LSB = hour 0) into 3 bytes
        $bitIndex = 0
        for ($b=0; $b -lt 3; $b++) {
            $byte = 0
            for ($bit=0; $bit -lt 8; $bit++) {
                if ($hours[$bitIndex]) { $byte = $byte -bor (1 -shl $bit) }
                $bitIndex++
            }
            $bytes[$day*3 + $b] = [byte]$byte
        }
    }
    return $bytes
}
function Get-LogonHoursPreset($name) {
    switch ($name.ToLower()) {
        '9-5-weekdays' {
            $sched = @{}
            0..4 | ForEach-Object { $sched[$_] = @(@(9,17)) }
            return New-LogonHoursBytes $sched
        }
        '24x7-allow' {
            $sched = @{}
            0..6 | ForEach-Object { $sched[$_] = @(@(0,24)) }
            return New-LogonHoursBytes $sched
        }
        'block-all' {
            return New-LogonHoursBytes @{}
        }
        default { throw "Unknown preset: $name" }
    }
}

# --- Actions ---
function Action-CreateUser {
    $ou = Read-Host "Target OU distinguishedName (e.g., OU=Sales,DC=contoso,DC=com)"
    $sam = Read-Host "sAMAccountName (e.g., jdoe)"
    $given = Read-Host "Given name"
    $sn = Read-Host "Surname"
    $display = Read-Host "Display name (or Enter to auto)"
    if ([string]::IsNullOrWhiteSpace($display)) { $display = "$given $sn" }
    $upnSuffix = Read-Host "UPN suffix (e.g., contoso.com)"
    $upn = "$sam@$upnSuffix"
    $dept = Read-Host "Department (optional)"
    $pwd = Read-Host "Initial password (will be set as temporary)" -AsSecureString

    if (-not (Confirm-Action "Create user $display ($sam) in $ou ?")) { return }

    $params = @{
        Name                  = $display
        SamAccountName        = $sam
        GivenName             = $given
        Surname               = $sn
        DisplayName           = $display
        UserPrincipalName     = $upn
        Path                  = $ou
        AccountPassword       = $pwd
        Enabled               = $true
        ChangePasswordAtLogon = $true
    }
    if ($dept) { $params['Department'] = $dept }

    if ($WhatIf) { New-ADUser @params -WhatIf }
    else { New-ADUser @params }

    Write-Host "User created." -ForegroundColor Green
}

function Action-RemoveUser {
    $id = Read-Host "User (sAMAccountName or UPN)"
    $u = Get-UserBySamOrUPN $id
    if (-not $u) { Write-Host "Not found." -ForegroundColor Yellow; return }
    if (-not (Confirm-Action "Remove user $($u.SamAccountName)?")) { return }
    if ($WhatIf) { Remove-ADUser -Identity $u -Confirm:$false -WhatIf }
    else { Remove-ADUser -Identity $u -Confirm:$false }
    Write-Host "User removed." -ForegroundColor Green
}

function Action-ResetPassword {
    $id = Read-Host "User (sAMAccountName or UPN)"
    $u = Get-UserBySamOrUPN $id
    $pwd = Read-Host "New password" -AsSecureString
    if ($WhatIf) { Set-ADAccountPassword -Identity $u -Reset -NewPassword $pwd -WhatIf }
    else { Set-ADAccountPassword -Identity $u -Reset -NewPassword $pwd }
    if ($WhatIf) { Set-ADUser -Identity $u -ChangePasswordAtLogon $true -WhatIf }
    else { Set-ADUser -Identity $u -ChangePasswordAtLogon $true }
    Write-Host "Password reset and 'change at next logon' enabled." -ForegroundColor Green
}

function Action-UnlockUser {
    $id = Read-Host "User (sAMAccountName or UPN)"
    $u = Get-UserBySamOrUPN $id
    if ($WhatIf) { Unlock-ADAccount -Identity $u -WhatIf }
    else { Unlock-ADAccount -Identity $u }
    Write-Host "Account unlocked." -ForegroundColor Green
}

function Action-CreateGroup {
    $ou = Read-Host "Target OU distinguishedName (for the group)"
    $name = Read-Host "Group name (CN)"
    $scope = Read-Host "Scope [Global|Universal|DomainLocal] (default Global)"
    if ([string]::IsNullOrWhiteSpace($scope)) { $scope = 'Global' }
    $cat = Read-Host "Category [Security|Distribution] (default Security)"
    if ([string]::IsNullOrWhiteSpace($cat)) { $cat = 'Security' }
    if ($WhatIf) { New-ADGroup -Name $name -GroupScope $scope -GroupCategory $cat -Path $ou -WhatIf }
    else { New-ADGroup -Name $name -GroupScope $scope -GroupCategory $cat -Path $ou }
    Write-Host "Group created." -ForegroundColor Green
}

function Action-AddToGroup {
    $user = Read-Host "User (sAMAccountName or UPN)"
    $group = Read-Host "Group (sAMAccountName or CN)"
    $u = Get-UserBySamOrUPN $user
    $g = Get-GroupBySamOrCN $group
    if ($WhatIf) { Add-ADGroupMember -Identity $g -Members $u -WhatIf }
    else { Add-ADGroupMember -Identity $g -Members $u }
    Write-Host "Added $($u.SamAccountName) to $($g.SamAccountName)." -ForegroundColor Green
}

function Action-RemoveFromGroup {
    $user = Read-Host "User (sAMAccountName or UPN)"
    $group = Read-Host "Group (sAMAccountName or CN)"
    $u = Get-UserBySamOrUPN $user
    $g = Get-GroupBySamOrCN $group
    if ($WhatIf) { Remove-ADGroupMember -Identity $g -Members $u -Confirm:$false -WhatIf }
    else { Remove-ADGroupMember -Identity $g -Members $u -Confirm:$false }
    Write-Host "Removed $($u.SamAccountName) from $($g.SamAccountName)." -ForegroundColor Green
}

function Action-MoveToOU {
    $id = Read-Host "User or Computer sAMAccountName"
    $targetOU = Read-Host "Target OU distinguishedName"
    $obj = try { Get-ADUser -Identity $id -ErrorAction Stop } catch { Get-ADComputer -Identity $id -ErrorAction SilentlyContinue }
    if (-not $obj) { Write-Host "Not found." -ForegroundColor Yellow; return }
    if ($WhatIf) { Move-ADObject -Identity $obj.DistinguishedName -TargetPath $targetOU -WhatIf }
    else { Move-ADObject -Identity $obj.DistinguishedName -TargetPath $targetOU }
    Write-Host "Moved $id to $targetOU." -ForegroundColor Green
}

function Action-SetUserMetadata {
    $id = Read-Host "User (sAMAccountName or UPN)"
    $u = Get-UserBySamOrUPN $id
    $dept = Read-Host "Department (Enter to skip)"
    $title = Read-Host "Title (Enter to skip)"
    $mgr = Read-Host "Manager (sAMAccountName/UPN) (Enter to skip)"
    $params = @{ Identity = $u }
    if ($dept) { $params['Department'] = $dept }
    if ($title) { $params['Title'] = $title }
    if ($mgr) {
        $m = Get-UserBySamOrUPN $mgr
        $params['Manager'] = $m.DistinguishedName
    }
    if ($WhatIf) { Set-ADUser @params -WhatIf } else { Set-ADUser @params }
    Write-Host "User attributes updated." -ForegroundColor Green
}

function Action-SetLoginHours {
    $id = Read-Host "User (sAMAccountName or UPN)"
    $u = Get-UserBySamOrUPN $id
    Write-Host "Presets: 1) 9-5-weekdays  2) 24x7-allow  3) block-all"
    $opt = Read-Host "Choose preset [1-3]"
    $name = switch ($opt) { '1' {'9-5-weekdays'} '2' {'24x7-allow'} '3' {'block-all'} default {'9-5-weekdays'} }
    $bytes = Get-LogonHoursPreset $name
    if ($WhatIf) { Set-ADUser -Identity $u -Replace @{logonHours=$bytes} -WhatIf }
    else { Set-ADUser -Identity $u -Replace @{logonHours=$bytes} }
    Write-Host "Logon hours set: $name" -ForegroundColor Green
}

function Action-SetFolderAccess {
    $path = Read-Host "Folder path (e.g., D:\Dept\Shared)"
    if (-not (Test-Path $path)) {
        if (Confirm-Action "Folder does not exist. Create $path ?") {
            if ($WhatIf) { New-Item -ItemType Directory -Path $path -WhatIf | Out-Null }
            else { New-Item -ItemType Directory -Path $path | Out-Null }
        } else { return }
    }
    $principal = Read-Host "User or Group (DOMAIN\name or name)"
    Write-Host "Rights: R=Read, M=Modify, F=FullControl; A=Add, D=Remove"
    $mode = Read-Host "Choose (e.g., A+M to add Modify, or D to remove all)"
    if ($mode -match '^d$') {
        icacls "$path" /remove "$principal" | Out-Null
        Write-Host "Removed explicit ACEs for $principal on $path" -ForegroundColor Green
        return
    }
    $right = if ($mode -match 'f') {'(F)'} elseif ($mode -match 'm') {'(M)'} else {'(R)'}
    # (OI)(CI) = inherit to files and subfolders
    $rule = "${principal}:(OI)(CI)$right"
    icacls "$path" /grant "$rule" | Out-Null
    Write-Host "Granted $right to $principal on $path (inheritable)." -ForegroundColor Green
}

function Action-NewGPOAndLink {
    if (-not (Get-Module -ListAvailable GroupPolicy)) {
        Write-Host "GroupPolicy module not available. Skipping." -ForegroundColor Yellow
        return
    }
    Import-Module GroupPolicy
    $name = Read-Host "GPO Name"
    $ou = Read-Host "Target OU distinguishedName (to link)"
    $gpo = if ($WhatIf) { New-GPO -Name $name -WhatIf } else { New-GPO -Name $name }
    if ($WhatIf) { New-GPLink -Name $name -Target $ou -Enforced:$false -LinkEnabled:$true -WhatIf }
    else { New-GPLink -Name $name -Target $ou -Enforced:$false -LinkEnabled:$true }
    Write-Host "Created GPO '$name' and linked to $ou." -ForegroundColor Green
    Write-Host "Tip: use Set-GPRegistryValue to configure specific policies within this GPO." -ForegroundColor DarkGray
}

function Show-Menu {
    Clear-Host
    Write-Host "================ AD Administration Menu ================" -ForegroundColor Cyan
    if ($WhatIf) {
        Write-Host "Mode: SIMULATION (no changes made)" -ForegroundColor Yellow
    } else {
        Write-Host "Mode: LIVE (changes will be applied)" -ForegroundColor Red
    }
@"
1) Create user
2) Remove user
3) Reset user password
4) Unlock user
5) Create group
6) Add user to group
7) Remove user from group
8) Move user/computer to OU (department)
9) Update user attributes (dept/title/manager)
10) Set user logon hours (presets)
11) Set folder access (NTFS) for user/group
12) Create + link a simple GPO to an OU
0) Exit
========================================================
"@
}

# --- Main ---
try {
    Ensure-ADModule

    do {
        Show-Menu
        $c = Read-Host "Choose an option"

        try {
            switch ($c) {
                '1'  { Action-CreateUser }
                '2'  { Action-RemoveUser }
                '3'  { Action-ResetPassword }
                '4'  { Action-UnlockUser }
                '5'  { Action-CreateGroup }
                '6'  { Action-AddToGroup }
                '7'  { Action-RemoveFromGroup }
                '8'  { Action-MoveToOU }
                '9'  { Action-SetUserMetadata }
                '10' { Action-SetLoginHours }
                '11' { Action-SetFolderAccess }
                '12' { Action-NewGPOAndLink }
                '0'  { }  # no-op; loop condition will end the program
                default { Write-Host "Invalid choice." -ForegroundColor Yellow }
            }
        } catch {
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        }

        if ($c -ne '0') { Pause-Enter }
    } while ($c -ne '0')

    Write-Host "Exiting AD Administration Tool..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1

} catch {
    Write-Host "Fatal: $($_.Exception.Message)" -ForegroundColor Red
}
