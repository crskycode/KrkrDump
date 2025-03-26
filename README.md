# Kirikiri Z File Dumper

This tool is designed to work with newer versions of the Kirikiri engine, enabling file extraction and analysis.

## Usage Instructions

The tool requires a JSON configuration file that must share the same base name as the DLL (e.g., `KrkrDump.dll` and `KrkrDump.json`).

### Configuration Example

```json
{
    "loglevel": 1,
    "enableExtract": true,
    "outputDirectory": "E:\\games\\game\\dump",
    "rules": [
        "file://\\./.+?\\.xp3>(.+?\\..+$)",
        "archive://./(.+)",
        "arc://./(.+)",
        "bres://./(.+)"
    ],
    "includeExtensions": [],
    "excludeExtensions": [
        ".ogg"
    ],
    "decryptSimpleCrypt": true
}
```

### Configuration Parameters

- **loglevel**: Controls diagnostic output verbosity:
  - `0`: No output
  - `1`: Standard logging
  - `2`: Detailed logging

- **enableExtract**: Enables file extraction when set to `true`.

- **outputDirectory**: Specifies the target directory for extracted files (use absolute paths).

- **rules**: Array of regular expressions for file filtering. Modify according to your requirements.

- **includeExtensions/excludeExtensions**: Filters files by extension (mutually exclusive). Empty arrays indicate no filtering.

- **decryptSimpleCrypt**: When enabled (`true`), attempts to decrypt text files protected with `SimpleCrypt` encryption.

## Installation and Execution

1. Prepare the configuration file as shown above.
2. Place the following files in the same directory:
   - `KrkrDump.dll`
   - `KrkrDump.json`
   - `KrkrDumpLoader.exe`
3. Launch the tool by dragging the game executable (`Game.exe`) onto `KrkrDumpLoader.exe`.
