# powerpkg

<br>

Portable software and configuration deployment facilitator tool for Windows enterprise networks.

<br>

![](/img/header.gif)

<br>

# Section

<br>

1. [Requirements](#requirements)
2. [Story](#story)
3. [How It Works](#how-it-works)
4. [Package File (`package.xml`)](#package-file-packagexml)
    - [Script Configuration (`<Configuration>`)](#script-configuration-configuration)
        - [PackageName](#packagename)
        - [BlockHost](#blockhost)
        - [SuppressNotification](#suppressnotification)
    - [Task Entry (`<TaskEntry>`)](#task-entry-taskentry)
        - [TaskName](#taskname)
        - [Executable](#executable)
        - [PlatformName](#platformname)
        - [PlatformVersion](#platformversion)
        - [Architecture](#architecture)
        - [TerminateProcess](#terminateprocess)
        - [TerminateMessage](#terminatemessage)
        - [SuccessExitCode](#successexitcode)
        - [ContinueIfFail](#continueiffail)
        - [VerifyInstall](#verifyinstall)
        - [SkipProcessCount](#skipprocesscount)
5. [Debugging](#debugging)
    - [Skipping Task Entries](#skipping-task-entries)
    - [Exit Codes](#exit-codes)

<br>

# Requirements

<br>

This project was written during a time when **Windows 7 SP1 (v6.1.7601)** and **PowerShell v3.0** were the common versions of these platforms in Windows enterprise environments. Subsequent versions of these platforms should be fully supported, too.

<br>

# Story

<br>

In 2015, when I was still part of the IT industry, I was working in a help desk position within a Microsoft environment. At the time, I had inherited the responsibility of overseeing this firm's software deployment and configuration management processes. This firm was utilizing Novell ZENworks (in an attempt) to conduct these processes across their network of laptops and workstations.

However, much like Windows itself, ZENworks functioned like a black box; unattended deployments were obscured and difficult to perform and debug. Every package had to be built using a basic, unscalable GUI wrapper on top of a buggy web interface. Management also recognized many of ZENworks' flaws, but their response was not assuring. Without prior consultation, management unanimously agreed to migrate to another proprietary, GUI-centric, third-party platform that proved to be only a marginal improvement.

Stuck between a dying platform and a future, but unpromising, successor, I created `powerpkg` in pursuit of a platform-agnostic and self-contained packaging solution. My goals were to establish agency over our package repository; achieve portability, maintainability and scalability; and allow for an easier switch between deployment platforms. Proudly so, I was successful in significantly alleviating the stress of this circumstance.

While I no longer work in the IT industry as of 2025, I continue to be a full-time computer hobbyist and write software out of pure passion. Do not hesitate to submit a ticket or contact me if an issue arises.

<br>

# How It Works

<br>

Hypothetically, consider this project as a means to accomplish a single task by packaging a portable Ansible executable alongside an Ansible playbook YAML file, and processing them locally.

The behavior of `powerpkg` is dependent upon an accompanying XML configuration file, [`package.xml`](#package-file-packagexml), that administrators can customize to their liking. For an example on how to build such a configuration yourself:

<br>

1. Save the following XML element inside a `package.xml` file alongside `powerpkg.ps1`:

```xml
<Package>
</Package>
```

2. Copy the following [script configuration](#script-configuration-configuration) XML element and paste it inside the `<Package>` XML element:

```xml
<Configuration>
	<PackageName>Example Package</PackageName>
	<BlockHost></BlockHost>
	<SuppressNotification>false</SuppressNotification>
</Configuration>
```

3. Copy the following [task entry](#task-entry-taskentry) XML element and paste it below the `<Configuration>` XML element:

```xml
<TaskEntry>
	<TaskName>Example Task Entry</TaskName>
	<Executable>powershell.exe -NoProfile Write-Host "Hello World!"</Executable>
</TaskEntry>
```

4. Ensure your package file (`package.xml`) appears as this example:

```xml
<Package>
	<Configuration>
		<PackageName>Example Package</PackageName>
		<BlockHost></BlockHost>
		<SuppressNotification>false</SuppressNotification>
	</Configuration>
	<TaskEntry>
		<TaskName>Example Task Entry</TaskName>
		<Executable>powershell.exe -NoProfile Write-Host "Hello World!"</Executable>
	</TaskEntry>
</Package>
```

5. Run `powerpkg.ps1`:

```shell
powershell.exe -NoProfile -ExecutionPolicy Unrestricted -File "powerpkg.ps1"
```

6. As `powerpkg.ps1` is running, you will notice output that is similar to the following example:

```
Initiating Package (Example Package):

Host                       : examplehost
Platform Name              : Windows
Platform Version           : 10.0
Architecture               : x64
User                       : user

----

Configuration Importation  : True
Suppress Notification      : False

----

(1) Example Task Entry:
[powershell.exe -NoProfile Write-Host "Hello World!"]

Hello World!

OK: (0)

----

Package Results (Example Package):

Tasks Processed : 1
 ^
 |
 |---- Success : 1
 +---- Failure : 0

OK: (0)
```

That's the gist of `powerpkg` and how it works!

The last line in the example output above, `OK: (0)`, reports the performance of `powerpkg.ps1` in the form of an exit code. In this case, the zero exit code indicates a successful deployment. As shown above, specific task entries report their own exit code. Such results are factored into the final exit code of `powerpkg.ps1`.

<br>

> [!NOTE]
> If `powerpkg.ps1` terminates with a non-zero exit code, determine its meaning in the [Debugging](#debugging) segment of this README.
>
> To further information on usage of `package.xml`, refer to the [Package File](#package-file-packagexml) segment of this README.

<br>

# Package File (`package.xml`)

<br>

A package file is a configuration file that features a series of instructions that determine:

- [What global options should be used when initially calling `powerpkg`](#script-configuration-configuration).
- [What commands and executables to call and what conditions should be met](#task-entry-taskentry).

Package files should be structured in the following manner:

```xml
<Package>
	<Configuration>
		<PackageName></PackageName>
		<BlockHost></BlockHost>
		<SuppressNotification></SuppressNotification>
	</Configuration>
	<TaskEntry>
		<TaskName></TaskName>
		<Executable></Executable>
		<PlatformVersion></PlatformVersion>
		<Architecture></Architecture>
		<TerminateProcess></TerminateProcess>
		<TerminateMessage></TerminateMessage>
		<SuccessExitCode></SuccessExitCode>
		<ContinueIfFail></ContinueIfFail>
		<VerifyInstall></VerifyInstall>
		<SkipProcessCount></SkipProcessCount>
	</TaskEntry>
</Package>
```

Which, with a bit of customization, can become the following example:

```xml
<Package>
	<Configuration>
		<PackageName>Example Package</PackageName>
		<BlockHost>examplehost1,examplehost2</BlockHost>
		<SuppressNotification>false</SuppressNotification>
	</Configuration>
	<TaskEntry>
		<TaskName>Example Task Entry</TaskName>
		<Executable>powershell.exe -NoProfile Write-Host "Hello World!"</Executable>
		<PlatformVersion>10.0</PlatformVersion>
		<Architecture>x64</Architecture>
		<TerminateProcess>example_process</TerminateProcess>
		<TerminateMessage>Example Program will terminate. Press OK to continue.</TerminateMessage>
		<SuccessExitCode>1234</SuccessExitCode>
		<ContinueIfFail>true</ContinueIfFail>
		<VerifyInstall>[Program]Example Program</VerifyInstall>
		<SkipProcessCount>false</SkipProcessCount>
	</TaskEntry>
	<TaskEntry>
		<TaskName>Another Example Task Entry</TaskName>
		<Executable>powershell.exe -NoProfile Write-Host "Hello New England!"</Executable>
	</TaskEntry>
	<TaskEntry>
		<TaskName>Yet Another Example Task Entry</TaskName>
		<Executable>msiexec.exe /i "[Package]example_program.msi" /qn /norestart</Executable>
		<VerifyInstall>[Program]Example Program</VerifyInstall>
	</TaskEntry>
</Package>
```

To familiarize yourself with `powerpkg`, continue reading the [Script Configuration](#script-configuration-configuration) and [Task Entry](#task-entry-taskentry) segments of this README. Examining the contents of the `\contrib\example_package` directory is also encouraged.

<br>

## Script Configuration (`<Configuration>`)

<br>

The `<Configuration>` element allows you to specify a few global options that process when initially running `powerpkg.ps1`. However, specifying this element is not required. If the element is absent from `package.xml`, default values for the parameters listed below will be used.

Only a single instance of the `<Configuration>` element is necessary inside `package.xml`.

```xml
<Configuration>
    <PackageName></PackageName>
    <BlockHost></BlockHost>
    <SuppressNotification></SuppressNotification>
</Configuration>
```

<br>

### `PackageName`

<br>

**Required**

No

**Purpose**

Specifies a custom name for a package.

**Default Value**

Base name of the package directory.

**Example**

```xml
<PackageName>Example Package</PackageName>
```

<br>

### `BlockHost`

<br>

**Required**

No

**Purpose**

Prevents specified hosts from processing a package.

**Default Value**

`null`

**Example**

```xml
<BlockHost>ABCDE12345</BlockHost>

<BlockHost>ABCDE12345,ABCDE67890</BlockHost>
```

#### Blocking a Range of Hosts

A range of hosts can also be blocked. If you have a set of machines whose **first** several characters are identical, such as the following example:

```
ABCDE1111
ABCDE2222
ABCDE3333
ABCDE4444
ABCDE5555
```

You can block the list of machines by specifying only `ABCDE`:

```xml
<BlockHost>ABCDE</BlockHost>
```

<br>

### `SuppressNotification`

<br>

**Required**

No

**Purpose**

Prevents a balloon notification from displaying upon a successful deployment.

**Default Value**

`true`

**Example**

```xml
<SuppressNotification>true</SuppressNotification>

<SuppressNotification>false</SuppressNotification>
```

<br>

## Task Entry (`<TaskEntry>`)

<br>

The `<TaskEntry>` element is responsible for handling conditionals and calls of commands and executables.

Multiple instances of the `<TaskEntry>` element can be processed within `package.xml`.

<br>

### `TaskName`

<br>

**Required**

Yes

**Purpose**

Name of an individual task entry.

**Example**

```xml
<TaskName>Install Program</TaskName>
```

<br>

> [!NOTE]
> For debugging purposes, you can temporarily skip task entries without having to remove them from `package.xml`. Refer to the [Skipping Task Entries](#skipping-task-entries) segment of this README.

<br>

### `Executable`

<br>

**Required**

Yes

**Purpose**

Command name or an executable path (relative or absolute) to call.

**Subparameters**

Name         | Description
------------ | -----------
`[Package]`  | Contains the absolute path of a package directory. Enables the ability to target a file or directory located inside a package directory.

#### Examples

```xml
<Executable>ipconfig.exe</Executable>

<Executable>msiexec.exe /i "[Package]example.msi" /qn /norestart</Executable>

<Executable>cmd.exe /q /c "[Package]example.bat"</Executable>

<Executable>"[Package]example.exe"</Executable>

<Executable>"[Package]example_directory\'example file with whitespace.exe'"</Executable>
```

#### Whitespace and Quotation Marks

When specifying a path containing whitespace, whether that path is an executable or part of an argument, it is recommended to encapsulate it with **double** quotation marks.

For arguments that reference individual file and / or directory names that contain whitespace, such file and / or directory names should be encapsulated by **single** quotation marks.

Here's an example that illustrates the use of single and double quotation marks:

```shell
powershell.exe -NoProfile "[Package]'an example.ps1'"

"C:\White Space\example.exe" /argument "D:\'More White Space'\Directory"
```

When using the `[Package]` subparameter, it is recommended to encapsulate an `Executable` value, and the subparameter itself, with double quotation marks. This prevents future I/O errors if the absolute path of the package directory ever changes and features whitespace.

#### Environment Variables

Unfortunately, direct use of environment variables is unsupported. As a workaround, you have two options:

1. Call `cmd.exe`:

```shell
cmd.exe /c notepad.exe %SYSTEMDRIVE%\test.txt
```

2. Call `powershell.exe`:
```shell
powershell.exe -NoProfile Start-Process -FileName notepad.exe -ArgumentList $env:SYSTEMDRIVE\test.txt -Wait
```

<br>

> [!WARNING]
> Before calling `powershell.exe`, minimize the risk of arbitrary code injection by using `-NoProfile`:
>
> ```shell
> powershell.exe -NoProfile Example-Command
> ```

<br>

### `PlatformName`

<br>

**Required**

No

**Purpose**

Platform name a task entry should be processed under.

**Example**

```xml
<PlatformName>Windows</PlatformName>

<PlatformName>Unix</PlatformName>
```

<br>

> [!WARNING]
> Issues will arise if `powerpkg` attempts to make use of Windows APIs and features on other platforms. For a similar (and superior) solution on other platforms, Ansible is strongly recommended.

<br>

### `PlatformVersion`

<br>

**Required**

No

**Purpose**

Kernel version a task entry should be processed under.

**Example**

```xml
<PlatformVersion>10.0</PlatformVersion>
```

<br>

> [!NOTE]
> Version matching works recursively. As an example, a version value of `6.1` will match with a specific kernel version of `6.1.7601`.

<br>

### `Architecture`

<br>

**Required**

No

**Purpose**

Userspace architecture a task entry should be processed under.

**Example**

```xml
<Architecture>x64</Architecture>

<Architecture>x86</Architecture>
```

<br>

### `TerminateProcess`

<br>

**Required**

No, except when utilizing the `TerminateMessage` parameter.

**Purpose**

Process, or list of process, to terminate prior to executable invocation.

**Example**

```xml
<TerminateProcess>explorer</TerminateProcess>

<TerminateProcess>explorer,notepad</TerminateProcess>
```

<br>

### `TerminateMessage`

<br>

**Required**

No

**Purpose**

Message to display to users prior to the termination of system processes. Used in conjunction with the `TerminateProcess` parameter.

**Example**

```xml
<TerminateMessage>File Explorer will terminate. When prepared, click on the OK button.</TerminateMessage>
```

<br>

### `SuccessExitCode`

<br>

**Required**

No

**Purpose**

Non-zero exit codes that indicate a successful task.

**Default Value**

`0`

**Example**

```xml
<SuccessExitCode>10</SuccessExitCode>

<SuccessExitCode>10,777,1000</SuccessExitCode>
```

<br>

> [!NOTE]
> The `0` exit code is accounted for, regardless of whether it is specified.

<br>

### `ContinueIfFail`

<br>

**Required**

No

**Purpose**

Whether to continue with remaining task entries if one task entry fails.

**Default Value**

`false`

**Values**

Value   | Result
-----   | ------
`true`  | `powerpkg` will continue processing remaining task entires.
`false` | `powerpkg` will stop processing remaining task entries, fail, and return a non-zero exit code.

**Example**

```xml
<ContinueIfFail>true</ContinueIfFail>
```

<br>

### `VerifyInstall`

<br>

**Required**

No, but any value specified must feature a subparameter.

**Purpose**

Skip a task entry if a program, hotfix, file / directory path, or a specific version of an executable exists.

**Subparameters**

Name             | Description                                                        | Argument   | Argument Required
------------     | -----------                                                        | ---------- | -----------------
`[Hotfix]`       | Verify the existence of a hotfix.                                  |            |
`[Path]`         | Verify the existence of a file or directory path.                  |            |
`[Vers_File]`    | Verify the file version of an executable file.                     | `[Build:]` | Yes
`[Vers_Product]` | Verify the product version of an executable file.                  | `[Build:]` | Yes
`[Program]`      | Verify the existence of an installed program name or product code. | `[Build:]` | No

**Example**

```xml
<VerifyInstall>[Hotfix]KB0000000</VerifyInstall>

<VerifyInstall>[Path]C:\example_file.exe</VerifyInstall>

<VerifyInstall>[Path]C:\example_directory</VerifyInstall>

<VerifyInstall>[Path]C:\example directory with whitespace</VerifyInstall>

<VerifyInstall>[Path]$env:SYSTEMDRIVE\example_directory</VerifyInstall>

<VerifyInstall>[Path]HKLM:\registry_path</VerifyInstall>

<VerifyInstall>[Path]env:\ENVIRONMENT_VARIABLE</VerifyInstall>

<VerifyInstall>[Vers_Product]C:\example_file.exe[Build:1.0]</VerifyInstall>

<VerifyInstall>[Vers_File]C:\example_file.exe[Build:1.0]</VerifyInstall>

<VerifyInstall>[Vers_File]$env:SYSTEMDRIVE\example_file.exe[Build:1.0]</VerifyInstall>

<VerifyInstall>[Program]{00000000-0000-0000-0000-000000000000}</VerifyInstall>

<VerifyInstall>[Program]{00000000-0000-0000-0000-000000000000}[Build:1.0]</VerifyInstall>

<VerifyInstall>[Program]Example Program</VerifyInstall>

<VerifyInstall>[Program]Example Program[Build:1.0]</VerifyInstall>
```

#### [Build:] Argument

Some `VerifyInstall` parameters make use of a **`[Build:]`** argument, allowing you to verify a specific version number associated with an installed program or executable file. To use this argument, you must specify it as a suffix of a `VerifyInstall` value. Then, insert a version number to the right of its colon. Take the following as an example, using `1.0` as a version number:

```xml
<VerifyInstall>[Vers_Product]C:\example_file.exe[Build:1.0]</VerifyInstall>
```

However, unlike the `PlatformVersion` parameter, whatever `[Build:]` version number you specify must be identical to the version number of the installed program or executable file you are targeting.

#### [Vers_File] and [Vers_Product] Subparameters

To retrieve the file or product version of an executable file for verification purposes, run the following command within PowerShell:

```powershell
[System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\example_file.exe") | Select FileVersion, ProductVersion
```

Then, you will notice the following output:

```
FileVersion       ProductVersion
-----------       --------------
1.0               1.0
```

Specify either value inside the `[Build:]` argument in the following manner:

```xml
<VerifyInstall>[Vers_File]C:\example_file.exe[Build:1.0]</VerifyInstall>

<VerifyInstall>[Vers_File]$env:SYSTEMDRIVE\example_file.exe[Build:1.0]</VerifyInstall>

<VerifyInstall>[Vers_Product]C:\example_file.exe[Build:1.0]</VerifyInstall>
```

#### [Program] Subparameter — Product Codes

Open the `Programs and Features` applet of the Windows Control Panel (`appwiz.cpl`) and retrieve the name of the installed program you wish to verify the existence of:

![Programs and Features](/img/example_verifyinstall_program.gif)

Open PowerShell and run the following command:

```powershell
Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | % {Get-ItemProperty $_.PSPath} | ? {$_.DisplayName -eq "Example Program"} | Select PSChildName
```

Or run the following command **if you're utilizing a i386 program on an AMD64 system**:

```powershell
Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | % {Get-ItemProperty $_.PSPath} | ? {$_.DisplayName -eq "Example Program"} | Select PSChildName
```

Then, you will notice the following product code:

```powershell
PSChildName
-----------
{00000000-0000-0000-0000-000000000000}
```

Finally, specify the product code in a task entry:

```xml
<VerifyInstall>[Program]{00000000-0000-0000-0000-000000000000}</VerifyInstall>
```

Alternatively, if you wish to verify the existence of a product code and version number of an installed program, use the `[Build:]` argument, using `1.0` as an example version number:

```xml
<VerifyInstall>[Program]{00000000-0000-0000-0000-000000000000}[Build:1.0]</VerifyInstall>
```

#### [Program] Subparameter — Program Name

Open the `Programs and Features` applet of the Windows Control Panel (`appwiz.cpl`) and retrieve the name of the installed program you wish to verify the existence of:

![Programs and Features](/img/example_verifyinstall_program.gif)

Then, specify the program name in a task entry:

```xml
<VerifyInstall>[Program]Example Program</VerifyInstall>
```

Alternatively, if you wish to verify the existence of a name and version number of an installed program, use the `[Build:]` argument, using `1.0` as an example version number:

```xml
<VerifyInstall>[Program]Example Program[Build:1.0]</VerifyInstall>
```

<br>

> [!NOTE]
> Usage of PowerShell environment variables, such as `$env:SYSTEMDRIVE`, is supported.
>
> Usage of quotation marks is not required, even for paths featuring whitespace.

<br>

### `SkipProcessCount`

<br>

**Required**

No

**Purpose**

Whether a task entry should be factored into the overall total of processed task entries, regardless of whether it succeeds or fails.

**Default Value**

`false`

**Values**

Value   | Result
-----   | ------
`true`  | Task entry will not be factored.
`false` | Task entry will be factored.

**Example**

```xml
<SkipProcessCount>true</SkipProcessCount>
```

<br>

# Debugging

<br>

## Skipping Task Entries

<br>

For debugging purposes, you can temporarily skip a task entry by specifying `#` as the first character in the `TaskName` parameter of the `<TaskEntry>` element in `package.xml` in the following fashion:

```xml
<TaskName>#Install Program</TaskName>
```

<br>

## Exit Codes

<br>

Code | Description
---- | -----------
1    | A task entry terminated with a non-zero exit code.
2    | An exception arose from a task entry during its processing.
3    | Initial task entry processing failed.
4    | A host has been prevented from processing a package.
5    | A package file was not found.
6    | No task entries were processed.
7    | A task entry is missing a required value.
