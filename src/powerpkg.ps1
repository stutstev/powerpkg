
<#
     ________  ________  ___       __   _______   ________  ________  ___  __    ________
    |\   __  \|\   __  \|\  \     |\  \|\  ___ \ |\   __  \|\   __  \|\  \|\  \ |\   ____\
    \ \  \|\  \ \  \|\  \ \  \    \ \  \ \   __/|\ \  \|\  \ \  \|\  \ \  \/  /|\ \  \___|
     \ \   ____\ \  \\\  \ \  \  __\ \  \ \  \_|/_\ \   _  _\ \   ____\ \   ___  \ \  \  ___
      \ \  \___|\ \  \\\  \ \  \|\__\_\  \ \  \_|\ \ \  \\  \\ \  \___|\ \  \\ \  \ \  \|\  \
       \ \__\    \ \_______\ \____________\ \_______\ \__\\ _\\ \__\    \ \__\\ \__\ \_______\
        \|__|     \|_______|\|____________|\|_______|\|__|\|__|\|__|     \|__| \|__|\|_______|


	.SYNOPSIS
	Portable software and configuration deployment facilitator tool for Windows enterprise networks.

	.NOTES
	MIT License
	Copyright (c) 2015-2025 Steven Peguero

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
#>

# = VARS =>

$ErrorActionPreference = "Stop"

$Script = @{}
$Script.Config = @{}
$Script.Config.BlockHost = $Null
$Script.Config.SuppressNotification  = $True
$Script.Config.TotalImported = 0  #  retrieves number of imported package-specified script preferences.
$Script.Config.ImportState = $Null  #  reports whether package-specified script preferences were imported.
$Script.CurrentDirectory = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$Script.CurrentPSVersion = $Host.Version.Major
$Script.ExitCode = 0
$Script.Output = $Null

$Machine = @{}
$Machine.Hostname = [System.Environment]::MachineName
$Machine.PlatformName = [System.Environment]::OSVersion.Platform
$Machine.PlatformVersion = [System.Environment]::OSVersion.Version.ToString()
$Machine.ProgramList = @()
$Machine.ProgramList += "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
$Machine.ProgramList += "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
$Machine.Username = [System.Environment]::UserName
$Machine.UserspaceArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture

$Package = @{}
$Package.Content = @{}
$Package.Content.All = $Null
$Package.Content.Configuration = $Null
$Package.Content.TaskEntry = $Null
$Package.Delimiter = ","
$Package.Name = Split-Path -Path $Script.CurrentDirectory -Leaf
$Package.Notification = @{}
$Package.Notification.Header += ("Installed ""{0}"" package!" -f $Package.Name)
$Package.Notification.Footer += "Questions or concerns? Please contact your system administrator."
$Package.Path = ("{0}\package.xml" -f $Script.CurrentDirectory)
$Package.TaskEntryStatus = @{}
$Package.TaskEntryStatus.Index = 0
$Package.TaskEntryStatus.Successful = 0
$Package.TaskEntryStatus.Unsuccessful = 0
$Package.TaskEntryStatus.TotalProcessed = 0
$Package.TaskEntryStatus.TotalFailedButContinued = 0
$Package.TaskEntrySubparameterRegexp = @{}
$Package.TaskEntrySubparameterRegexp.Executable = @{}
$Package.TaskEntrySubparameterRegexp.Executable.Package = "(\[)Package(\])"  #  var that replaces matching string with package dir path.
$Package.TaskEntrySubparameterRegexp.Executable.Sanitizer = @()  #  reg exps that remove arbitrary commands.
$Package.TaskEntrySubparameterRegexp.Executable.Sanitizer += "\;(.*)$"
$Package.TaskEntrySubparameterRegexp.Executable.Sanitizer += "\&(.*)$"
$Package.TaskEntrySubparameterRegexp.Executable.Sanitizer += "\|(.*)$"
$Package.TaskEntrySubparameterRegexp.Executable.Sanitizer += "(\s+)$"
$Package.TaskEntrySubparameterRegexp.VerifyInstall = @{}
$Package.TaskEntrySubparameterRegexp.VerifyInstall.Arg_Build = "\[Build:(.*)\]$"
$Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Hotfix = "^(\[)Hotfix(\])"
$Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Path = "^(\[)Path(\])"
$Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Version_FileInfo = "^(\[)Vers_File(\])"
$Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Version_ProductInfo = "^(\[)Vers_Product(\])"
$Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Program = "^(\[)Program(\])"
$Package.TaskEntrySubparameterRegexp.VerifyInstall.Value_MSIGUID = "^\{(.*)\}$"
$Package.Variable = @{}
$Package.Variable.TerminateProcess = @{}
$Package.Variable.TerminateProcess.AlreadyPrompted = $False  #  ensures to only display TerminateMessage prompt once if terminating more than one process.
$Package.Variable.VerifyInstall = @{}
$Package.Variable.VerifyInstall.SpecifiedBuild = $Null
$Package.Variable.VerifyInstall.DiscoveredBuild = $Null
$Package.Variable.VerifyInstall.Existence = $Null
$Package.Variable.VerifyInstall.ProgramReference = $Null

$TaskEntry = @{}
$TaskEntry.TaskName = $Null
$TaskEntry.Executable = $Null
$TaskEntry.PlatformName = $Null
$TaskEntry.PlatformVersion = $Null
$TaskEntry.Architecture = $Null
$TaskEntry.TerminateProcess = $Null
$TaskEntry.TerminateMessage = $Null
$TaskEntry.VerifyInstall = $Null
$TaskEntry.SuccessExitCode = $Null
$TaskEntry.ContinueIfFail = $Null
$TaskEntry.SkipProcessCount = $Null

# = FUNC =>

function Get-EnvironmentVariableValue
{
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        $Path
    )

	$Function = @{}
	$Function.EnvironmentVariableSyntax        = @{}
	$Function.EnvironmentVariableSyntax.Before = "^(\$)env(\:)"
	$Function.EnvironmentVariableSyntax.After  = "env:\"
	$Function.Path                             = $Path
	$Function.Result                           = $Null

    foreach ($Item in $Function.Path -split "\\")
    {
        if ($Item -match $Function.EnvironmentVariableSyntax.Before)
        {
            $Item = $Item -replace ($Function.EnvironmentVariableSyntax.Before, $Function.EnvironmentVariableSyntax.After)

            try
            {
                $Item = (Get-Content $Item -ErrorAction Stop)
            }
            catch [Exception]
            {
                continue
            }
        }

        $Function.Result += @($Item)
    }

    return ($Function.Result -join "\")
}

function Invoke-Executable
{
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        $Path
    )

	$Invocation                              = @{}
	$Invocation.Input                        = $Path
	$Invocation.Executable                   = @{}
	$Invocation.Executable.Value             = $Null
	$Invocation.Executable.Quoted            = "^(\"")(.*)(\"")"
	$Invocation.Executable.Unquoted          = "^(\S+)"
	$Invocation.Arguments                    = @{}
	$Invocation.Arguments.Value              = $Null
	$Invocation.Arguments.LeftwardWhitespace = "^(\s+)(.*)"

    #  split executable and its arguments:

    if ($Invocation.Input -match $Invocation.Executable.Quoted)
    {
        $Invocation.Executable.Value = $Invocation.Input -match $Invocation.Executable.Quoted
        $Invocation.Executable.Value = $Matches[2]
        $Invocation.Arguments.Value  = $Invocation.Input -replace ($Invocation.Executable.Quoted, "")
    }
    else
    {
        $Invocation.Executable.Value = $Invocation.Input -match $Invocation.Executable.Unquoted
        $Invocation.Executable.Value = $Matches[1]
        $Invocation.Arguments.Value  = $Invocation.Input -replace ($Invocation.Executable.Unquoted, "")
    }

    #  remove potential whitespace between executable and arguments:

    if ($Invocation.Arguments.Value -match $Invocation.Arguments.LeftwardWhitespace)
    {
        $Invocation.Arguments.Value = $Invocation.Arguments.Value -match $Invocation.Arguments.LeftwardWhitespace
        $Invocation.Arguments.Value = $Matches[2]
    }

    try
    {
        $ProcessStartInfo                        = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessStartInfo.FileName               = $Invocation.Executable.Value
        $ProcessStartInfo.RedirectStandardError  = $True
        $ProcessStartInfo.RedirectStandardOutput = $True
        $ProcessStartInfo.UseShellExecute        = $False
        $ProcessStartInfo.Arguments              = $Invocation.Arguments.Value

        $Process           = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessStartInfo
        $Process.Start() | Out-Null
        $Process.WaitForExit()

        $Result = New-Object PSObject -Property @{
            "ExitCode" = $Process.ExitCode
            "Output"   = $Process.StandardOutput.ReadToEnd()
        }

        return $Result
    }
    catch [Exception]
    {
        throw
    }
}

function pass
{
	return
}

function Show-BalloonTip
{
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param (
        [Parameter(Mandatory = $True)]
        $Title,

        [Parameter(Mandatory = $False)]
        $Text = " ",

        [Parameter(Mandatory = $False)]
        [ValidateSet("None", "Info", "Warning", "Error")]
        $Icon = "Info",

        [Parameter(Mandatory = $False)]
        $Timeout = 10000
    )

    $Script:Balloon -eq $null

    Add-Type -AssemblyName System.Windows.Forms

    if ($Script:Balloon -eq $Null)
    {
        $Script:Balloon = New-Object System.Windows.Forms.NotifyIcon
    }

    $Path                    = Get-Process -Id $PID | Select-Object -ExpandProperty Path
    $Balloon.Icon            = [System.Drawing.Icon]::ExtractAssociatedIcon($Path)
    $Balloon.BalloonTipIcon  = $Icon
    $Balloon.BalloonTipText  = $Text
    $Balloon.BalloonTipTitle = $Title
    $Balloon.Visible         = $True

    $Balloon.ShowBalloonTip($Timeout)
}

function Show-DialogBox
{
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        $Title,

        [Parameter(Mandatory = $True)]
        [String]
        $Message
    )

    $Wscript = New-Object -COMObject Wscript.Shell
    $Wscript.Popup($Message, 0, $Title, 0x0)
}

function Write-Result
{
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        $Status,

        [Parameter(Mandatory = $False)]
        [String]
        $Code = "",

        [Parameter(Mandatory = $False)]
        [String]
        $Output,

        [Parameter(Mandatory = $False)]
        [Switch]
        $AddNewLine
    )

    [String]$Result = ""

    if ($Output -notmatch "^$")
    {
        if ($AddNewLine)
        {
            $Result += ("{0}`n`n" -f $Output)
        }
        else
        {
            $Result += ("{0}`n" -f $Output)
        }
    }

    if ($Code -notmatch "^$")
    {
        $Code = (": ({0})" -f $Code)
    }

    $Result += ("{0}{1}`n`n----" -f $Status, $Code)

    return $Result
}

# = MAIN =>

# = PACKAGE IMPORT =>

try
{
    if (Test-Path $Package.Path)
    {
        [XML]$Package.Content.All      = Get-Content $Package.Path
        $Package.Content.Configuration = $Package.Content.All.Package.Configuration
        $Package.Content.TaskEntry     = $Package.Content.All.Package.TaskEntry
    }
    else
    {
        throw "No package file was present within the package directory."
    }
}
catch [Exception]
{
    Write-Host -ForegroundColor Red ("`nERROR: A package file could not be imported. Details: {0}" -f $Error[0])
    [Environment]::Exit(5)
}

# = PACKAGE > CONFIG =>

if ($Package.Content.Configuration.BlockHost -notmatch "^$")
{
    $Script.Config.BlockHost = $Package.Content.Configuration.BlockHost -split ($Package.Delimiter)
    $Script.Config.TotalImported++
}

if ($Package.Content.Configuration.PackageName -notmatch "^$")
{
    $Package.Name = $Package.Content.Configuration.PackageName
    $Script.Config.TotalImported++
}

if ($Package.Content.Configuration.SuppressNotification -eq $False)
{
    $Script.Config.SuppressNotification = $False
    $Script.Config.TotalImported++
}

if ($Script.Config.TotalImported -gt 0)
{
    $Script.Config.ImportState = $True
}
else
{
    $Script.Config.ImportState = $False
}

# = PACKAGE > CONFIG > BLOCKHOST =>

foreach ($ImportedHostname in $Script.Config.BlockHost)
{
    if ($Machine.Hostname -match $ImportedHostname -and $ImportedHostname -notmatch "^$")
    {
        Write-Host -ForegroundColor Red ("`nERROR: Package ""{0}"" will not be processed. This host is blocked.`n" -f $Package.Name)
        [Environment]::Exit(4)
    }
}

# = PACKAGE > INFO > CONFIG / ENV =>

Write-Host -ForegroundColor Cyan (
"
Initiating Package ($($Package.Name)):

Host                      : $($Machine.Hostname)
Platform                  : $($Machine.PlatformName)
Version                   : $($Machine.PlatformVersion)
Architecture              : $($Machine.UserspaceArchitecture)
User                      : $($Machine.Username)

----

Configuration Importation : $($Script.Config.ImportState)
Suppress Notification     : $($Script.Config.SuppressNotification)

----
"
)

# = PACKAGE > TASK =>

foreach ($Item in $Package.Content.TaskEntry)
{
    try
    {
        $TaskEntry.TaskName         = $Item.TaskName
        $TaskEntry.Executable       = $Item.Executable
        $TaskEntry.PlatformName     = $Item.PlatformName
        $TaskEntry.PlatformVersion  = $Item.PlatformVersion
        $TaskEntry.Architecture     = $Item.Architecture
        $TaskEntry.TerminateProcess = $Item.TerminateProcess
        $TaskEntry.TerminateMessage = $Item.TerminateMessage
        $TaskEntry.VerifyInstall    = $Item.VerifyInstall
        $TaskEntry.SuccessExitCode  = $Item.SuccessExitCode
        $TaskEntry.ContinueIfFail   = $Item.ContinueIfFail
        $TaskEntry.SkipProcessCount = $Item.SkipProcessCount
    }
    catch [Exception]
    {
        $Script.Output = ("`nTask Entry ({0}): {1}" -f $TaskEntry.TaskName, $Error[0])
        Write-Host -ForegroundColor Red (Write-Result -Status "ERROR" -Code 3 -Output $Script.Output -AddNewLine)

        $Script.ExitCode = 3
        break
    }

	# = PACKAGE > TASK > ENTRY > TASKNAME =>

    $Package.TaskEntryStatus.Index = $Package.TaskEntryStatus.Index + 1

    if ($TaskEntry.TaskName -match "^$" -or $TaskEntry.TaskName -match "^(\s+)$")
    {
        $Script.Output = ("`nTaskName: Specification is required for ""{0}"" at Task Entry {1}." -f $TaskEntry.Executable, [String]$Package.TaskEntryStatus.Index)
        Write-Host -ForegroundColor Red (Write-Result -Status "ERROR" -Code 7 -Output $Script.Output -AddNewLine)

        $Script.ExitCode = 7
        break
    }
    elseif ($TaskEntry.TaskName -match "^\#")
    {
        continue
    }

	# = PACKAGE > TASK > ENTRY > EXECUTABLE =>

    if ($TaskEntry.Executable -match "^$" -or $TaskEntry.Executable -match "^(\s+)$")
    {
        $Script.Output = ("`nExecutable: Specification is required for ""{0}"" at Task Entry {1}." -f $TaskEntry.TaskName, [String]$Package.TaskEntryStatus.Index)
        Write-Host -ForegroundColor Red (Write-Result -Status "ERROR" -Code 7 -Output $Script.Output -AddNewLine)

        $Script.ExitCode = 7
        break
    }
    elseif ($TaskEntry.Executable -match $Package.TaskEntrySubparameterRegexp.Executable.Package)
    {
        $TaskEntry.Executable = $TaskEntry.Executable -Replace ($Package.TaskEntrySubparameterRegexp.Executable.Package, ("{0}\" -f $Script.CurrentDirectory))
    }

    foreach ($Item in $Package.TaskEntrySubparameterRegexp.Executable.Sanitizer)
    {
        $TaskEntry.Executable = $TaskEntry.Executable -replace ($Item, "")
    }

    #  display current taskname and executable strings:
    Write-Host -NoNewLine ("`n({0}) {1}: " -f $Package.TaskEntryStatus.Index, $TaskEntry.TaskName)
    Write-Host -ForegroundColor Cyan ("`n[{0}]`n" -f $TaskEntry.Executable)

	# = PACKAGE > TASK > ENTRY > PLATFORMNAME =>

    if ($TaskEntry.PlatformName -match "^$" -or $Machine.PlatformName -match $TaskEntry.PlatformName)
    {
        pass
    }
    else
    {
        $Script.Output = ("PlatformName: ""{0}"" is a requirement." -f $TaskEntry.PlatformName)

        Write-Host -ForegroundColor Yellow (Write-Result -Status "SKIP" -Output $Script.Output -AddNewLine)
        continue
    }

	# = PACKAGE > TASK > ENTRY > PLATFORMVERSION =>

    if ($TaskEntry.PlatformVersion -match "^$" -or $Machine.PlatformVersion -match $TaskEntry.PlatformVersion)
    {
        pass
    }
    else
    {
        $Script.Output = ("PlatformVersion: ""{0}"" is a requirement." -f $TaskEntry.PlatformVersion)

        Write-Host -ForegroundColor Yellow (Write-Result -Status "SKIP" -Output $Script.Output -AddNewLine)
        continue
    }

	# = PACKAGE > TASK > ENTRY > ARCHITECTURE =>

    if ($TaskEntry.Architecture -match "^$" -or $TaskEntry.Architecture -match $Machine.UserspaceArchitecture)
    {
        pass
    }
    else
    {
        $Script.Output = ("Architecture: ""{0}"" is a requirement." -f $TaskEntry.Architecture)

        Write-Host -ForegroundColor Yellow (Write-Result -Status "SKIP" -Output $Script.Output -AddNewLine)
        continue
    }

	# = PACKAGE > TASK > ENTRY > VERIFYINSTALL > HOTFIX =>

    if ($TaskEntry.VerifyInstall -match $Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Hotfix)
    {
        $TaskEntry.VerifyInstall                  = $TaskEntry.VerifyInstall -replace ($Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Hotfix, "")
        $Package.Variable.VerifyInstall.Existence = Get-Hotfix | ? {$_.HotfixID -eq $TaskEntry.VerifyInstall}

        if ($Package.Variable.VerifyInstall.Existence -ne $Null)
        {
            $Script.Output = ("VerifyInstall: [Hotfix] ""{0}"" exists." -f $TaskEntry.VerifyInstall)

            Write-Host -ForegroundColor Yellow (Write-Result -Status "SKIP" -Output $Script.Output -AddNewLine)
            continue
        }
    }

	# = PACKAGE > TASK > ENTRY > VERIFYINSTALL > PATH =>

    elseif ($TaskEntry.VerifyInstall -match $Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Path)
    {
        $TaskEntry.VerifyInstall                  = $TaskEntry.VerifyInstall -replace ($Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Path, "")
        $TaskEntry.VerifyInstall                  = Get-EnvironmentVariableValue -Path $TaskEntry.VerifyInstall
        $Package.Variable.VerifyInstall.Existence = Test-Path $TaskEntry.VerifyInstall

        if ($Package.Variable.VerifyInstall.Existence -eq $True)
        {
            $Script.Output = ("VerifyInstall: [Path] ""{0}"" exists." -f $TaskEntry.VerifyInstall)

            Write-Host -ForegroundColor Yellow (Write-Result -Status "SKIP" -Output $Script.Output -AddNewLine)
            continue
        }
    }

	# = PACKAGE > TASK > ENTRY > VERIFYINSTALL > FILEINFO =>

    elseif ($TaskEntry.VerifyInstall -match $Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Version_FileInfo)
    {
        $TaskEntry.VerifyInstall = $TaskEntry.VerifyInstall -replace ($Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Version_FileInfo, "")

        try
        {
            #  separates arg_build (version / build number) and verifyinstall value (file path):
            $TaskEntry.VerifyInstall -match $Package.TaskEntrySubparameterRegexp.VerifyInstall.Arg_Build | Out-Null

            $TaskEntry.VerifyInstall                        = $TaskEntry.VerifyInstall -replace ($Package.TaskEntrySubparameterRegexp.VerifyInstall.Arg_Build, "")
            $TaskEntry.VerifyInstall                        = Get-EnvironmentVariableValue -Path $TaskEntry.VerifyInstall
            $Package.Variable.VerifyInstall.SpecifiedBuild  = $Matches[1]
            $Package.Variable.VerifyInstall.DiscoveredBuild = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($TaskEntry.VerifyInstall) | % {$_.FileVersion}

            #  determines whether both arg_build and version / build number of verifyinstall value (file path) match:
            if ($Package.Variable.VerifyInstall.SpecifiedBuild -eq $Package.Variable.VerifyInstall.DiscoveredBuild)
            {
                $Script.Output = ("VerifyInstall: [Vers_File] ""{0}"" exists." -f $Package.Variable.VerifyInstall.SpecifiedBuild)

                Write-Host -ForegroundColor Yellow (Write-Result -Status "SKIP" -Output $Script.Output -AddNewLine)
                continue
            }
            else
            {
                throw
            }
        }
        catch [Exception]
        {
            pass
        }
    }

	# = PACKAGE > TASK > ENTRY > VERIFYINSTALL > PRODUCTINFO =>

    elseif ($TaskEntry.VerifyInstall -match $Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Version_ProductInfo)
    {
        $TaskEntry.VerifyInstall = $TaskEntry.VerifyInstall -replace ($Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Version_ProductInfo, "")

        try
        {
            #  separates arg_build (version / build number) and verifyinstall value (file path):
            $TaskEntry.VerifyInstall -match $Package.TaskEntrySubparameterRegexp.VerifyInstall.Arg_Build | Out-Null

            $TaskEntry.VerifyInstall                        = $TaskEntry.VerifyInstall -replace ($Package.TaskEntrySubparameterRegexp.VerifyInstall.Arg_Build, "")
            $TaskEntry.VerifyInstall                        = Get-EnvironmentVariableValue -Path $TaskEntry.VerifyInstall
            $Package.Variable.VerifyInstall.SpecifiedBuild  = $Matches[1]
            $Package.Variable.VerifyInstall.DiscoveredBuild = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($TaskEntry.VerifyInstall) | % {$_.ProductVersion}

            #  determines whether both arg_build and version / build number of verifyinstall value (file path) match:
            if ($Package.Variable.VerifyInstall.SpecifiedBuild -eq $Package.Variable.VerifyInstall.DiscoveredBuild)
            {
                $Script.Output = ("VerifyInstall: [Vers_Product] ""{0}"" exists." -f $Package.Variable.VerifyInstall.SpecifiedBuild)

                Write-Host -ForegroundColor Yellow (Write-Result -Status "SKIP" -Output $Script.Output -AddNewLine)
                continue
            }
            else
            {
                throw
            }
        }
        catch [Exception]
        {
            pass
        }
    }

	# = PACKAGE > TASK > ENTRY > VERIFYINSTALL > PROGRAM =>

    elseif ($TaskEntry.VerifyInstall -match $Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Program)
    {
        $TaskEntry.VerifyInstall = $TaskEntry.VerifyInstall -replace ($Package.TaskEntrySubparameterRegexp.VerifyInstall.Type_Program, "")

        try
        {
			#  if verifyinstall value does not contain the arg_build argument.
            if ($TaskEntry.VerifyInstall -notmatch $Package.TaskEntrySubparameterRegexp.VerifyInstall.Arg_Build)
            {

                #  determines whether verifyinstall value is an msi guid in order to reference correct property:
                if ($TaskEntry.VerifyInstall -match $Package.TaskEntrySubparameterRegexp.VerifyInstall.Value_MSIGUID)
                {
                    $Package.Variable.VerifyInstall.ProgramReference = "PSChildName"
                }
                else
                {
                    $Package.Variable.VerifyInstall.ProgramReference = "DisplayName"
                }

                #  searches registry for possible program name or msi guid that matches verifyinstall value:
                foreach ($Path in $Machine.ProgramList)
                {
                    if (Test-Path $Path)
                    {
                        $Package.Variable.VerifyInstall.Existence += @(
                            Get-ChildItem $Path | % {Get-ItemProperty $_.PSPath} | ? {$_.$($Package.Variable.VerifyInstall.ProgramReference) -eq $TaskEntry.VerifyInstall} | % {$_.DisplayName}
                        )
                    }
                }

                #  determines whether or matching program code or msi guid was found:
                if ($Package.Variable.VerifyInstall.Existence -ne $Null)
                {
                    $Script.Output = ("VerifyInstall: [Program] ""{0}"" exists." -f $TaskEntry.VerifyInstall)

                    Write-Host -ForegroundColor Yellow (Write-Result -Status "SKIP" -Output $Script.Output -AddNewLine)
                    continue
                }
                else
                {
                    throw
                }
            }
            else
            {
                #  separates arg_build (version / build number) and verifyinstall value (program name / msi guid):
                $TaskEntry.VerifyInstall -match $Package.TaskEntrySubparameterRegexp.VerifyInstall.Arg_Build | Out-Null
                $TaskEntry.VerifyInstall                       = $TaskEntry.VerifyInstall -replace ($Package.TaskEntrySubparameterRegexp.VerifyInstall.Arg_Build, "")
                $Package.Variable.VerifyInstall.SpecifiedBuild = $Matches[1]

                #  determines whether verifyinstall value is an msi guid in order to reference correct property:
                if ($TaskEntry.VerifyInstall -match $Package.TaskEntrySubparameterRegexp.VerifyInstall.Value_MSIGUID)
                {
                    $Package.Variable.VerifyInstall.ProgramReference = "PSChildName"
                }
                else
                {
                    $Package.Variable.VerifyInstall.ProgramReference = "DisplayName"
                }

                #  searches registry for possible program name or msi guid that matches verifyinstall value:
                foreach ($Path in $Machine.ProgramList)
                {
                    if (Test-Path $Path)
                    {
                        $Package.Variable.VerifyInstall.DiscoveredBuild += @(
                            Get-ChildItem $Path | % {Get-ItemProperty $_.PSPath} | ? {$_.$($Package.Variable.VerifyInstall.ProgramReference) -eq $TaskEntry.VerifyInstall} | % {$_.DisplayVersion}
                        )
                    }
                }

                #  determines whether there is a match between discovered program name / msi guid's respective version / build number and arg_build:
                if ($Package.Variable.VerifyInstall.DiscoveredBuild -contains $Package.Variable.VerifyInstall.SpecifiedBuild)
                {
                    $Script.Output = ("VerifyInstall: [Program] ""{0}"" exists." -f $Package.Variable.VerifyInstall.SpecifiedBuild)

                    Write-Host -ForegroundColor Yellow (Write-Result -Status "SKIP" -Output $Script.Output -AddNewLine)
                    continue
                }
            }
        }
        catch [Exception]
        {
            pass
        }
    }

	# = PACKAGE > TASK > ENTRY > TERMINATEPROCESS =>

    if ($TaskEntry.TerminateProcess -notmatch "^$")
    {
        $TaskEntry.TerminateProcess = $TaskEntry.TerminateProcess -split ($Package.Delimiter)

        foreach ($Process in $TaskEntry.TerminateProcess)
        {
            try
            {
                if (Get-Process $Process)
                {
                    pass
                }
                else
                {
                    continue
                }

                if ($TaskEntry.TerminateMessage -notmatch "^$" -and $Package.Variable.TerminateProcess.AlreadyPrompted -eq $False)
                {
                    Show-DialogBox -Title $Package.Name -Message $TaskEntry.TerminateMessage | Out-Null
                    $Package.Variable.TerminateProcess.AlreadyPrompted = $True
                }

                Get-Process $Process | Stop-Process -Force
            }
            catch [Exception]
            {
                continue
            }
        }
    }

	# = PACKAGE > TASK > ENTRY > SUCCESSEXITCODE =>

    if ($TaskEntry.SuccessExitCode -eq $Null)
    {
        $TaskEntry.SuccessExitCode = 0
    }
    else
    {
        $TaskEntry.SuccessExitCode  = $TaskEntry.SuccessExitCode -split ($Package.Delimiter)
        $TaskEntry.SuccessExitCode += 0
    }

	# = PACKAGE > TASK > EXECUTION =>

    try
    {
        $Script.Output = (Invoke-Executable -Path $TaskEntry.Executable)

        if ($TaskEntry.SuccessExitCode -contains $Script.Output.ExitCode)
        {
            Write-Host -ForegroundColor Green (Write-Result -Status "OK" -Code $Script.Output.ExitCode -Output $Script.Output.Output)

            if ($TaskEntry.SkipProcessCount -ne "true")
            {
                $Package.TaskEntryStatus.Successful++
            }
            else
            {
                continue
            }
        }
        else
        {
            Write-Host -ForegroundColor Red (Write-Result -Status "WARN" -Code $Script.Output.ExitCode -Output $Script.Output.Output)

            if ($TaskEntry.SkipProcessCount -ne "true")
            {
                $Package.TaskEntryStatus.Unsuccessful++
            }

            if ($TaskEntry.ContinueIfFail -ne "true")
            {
                $Script.ExitCode = 1
                break
            }
            else
            {
                $Package.TaskEntryStatus.TotalFailedButContinued++
                continue
            }
        }
    }
    catch [Exception]
    {
        $Script.Output = ("Executable Invocation: {0}" -f $Error[0])
        Write-Host -ForegroundColor Red (Write-Result -Status "ERROR" -Code 2 -Output $Script.Output -AddNewLine)

        if ($TaskEntry.SkipProcessCount -ne "true")
        {
            $Package.TaskEntryStatus.Unsuccessful++
        }

        if ($TaskEntry.ContinueIfFail -ne "true")
        {
            $Script.ExitCode = 2
            break
        }
        else
        {
            $Package.TaskEntryStatus.TotalFailedButContinued++
            continue
        }
    }
}

# = PACKAGE > INFO > FINAL REPORT =>

if ($Package.TaskEntryStatus.Successful -eq 0 -and $Package.TaskEntryStatus.Unsuccessful -eq 0)
{
    Write-Host -ForegroundColor Red "`nWARN: No task entries were processed.`n"

    if ($Script.ExitCode -eq 0)
    {
        $Script.ExitCode = 6
    }
}
else
{
    $Package.TaskEntryStatus.TotalProcessed = [Int]$Package.TaskEntryStatus.Successful + [Int]$Package.TaskEntryStatus.Unsuccessful

	$Script.Output = (
"
Tasks Processed : $($Package.TaskEntryStatus.TotalProcessed)
  ^
  |
  |---- Success : $($Package.TaskEntryStatus.Successful)
  +---- Failure : $($Package.TaskEntryStatus.Unsuccessful)
"
	)

    Write-Host ("`nPackage Results ({0}):" -f $Package.Name)

    if ($Script.ExitCode -eq 0)
    {
        $Script.Output += ("`nOK: ({0})`n" -f $Script.ExitCode)

        Write-Host -ForegroundColor Green $Script.Output

        if ($Script.Config.SuppressNotification -eq $False)
        {
            Show-BalloonTip -Title $Package.Notification.Header -Text $Package.Notification.Footer | Out-Null
        }
    }
    else
    {
        $Script.Output += ("`nERROR: ({0})`n" -f $Script.ExitCode)

        Write-Host -ForegroundColor Red $Script.Output
    }
}

[Environment]::Exit($Script.ExitCode)
