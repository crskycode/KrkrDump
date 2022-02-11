# Kirikiri Z File Dumper

This tool can works with for some new engines.

## How to use

The tool reads a json-based config file when it starts up. That config file should have the same name as the dll. e.g `KrkrDump.json`

Here is an example of a valid config file:

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

`loglevel`: Represent how diagnostic information outputs. Set to `0` means turn off any output. Set to `1` or `2` for more detail.

`enableExtract`: Set to true when you want to extract files from game.

`outputDirectory`: Path that you want to put the extracted files into.

`rules`: Uses regular expression to filter the files. Add/remove as you intended.

`includeExtensions`,`excludeExtensions`: Filter the file type that you want to extract. Exclusive.

`decryptSimpleCrypt`: Try to decrypt the text file encrypted with `SimpleCrypt`.

## How to start

If your config file is ready, put `KrkrDump.dll` and `KrkrDump.json` and `KrkrDumpLoader.exe` in the same folder, then drag `Game.exe` to `KrkrDumpLoader.exe`
