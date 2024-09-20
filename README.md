# ActivitesCache Execution

Gets the execution of files using the activitiescache.db artifact using sqlite3, checks the files' digital signatures, and applies several generic YARA rules used for detecting Minecraft cheats.

## What does it do?

- Parses executed files using activitiescache.db with sqlite3
- Checks digital signatures for each file present (reports "Deleted" if not found)
- Detects specific digital signatures (e.g., Slinky and Vape)
- Applies generic checks to each present file

## Generics:

1. **Generic A**: Basic strings for autoclickers
2. **Generic A2**: Basic imports for autoclickers
3. **Generic B**: Generic protection detection for non-C# files
4. **Generic B2**: Generic protection detection for non-C# files
5. **Generic B3**: Generic protection detection for non-C# files
6. **Generic C**: Basic generic protection detection for C# files

Note: All generics should be relatively safe, but don't panic if they trigger. A2 generic may cause occasional "false flags", which are not intended to be fixed to maintain detection of real cheats.

## How to use?

ActivitesCache Execution offers two modes of operation:

### 1. Normal Mode

1. Simply open the `.exe` file
2. The program will:
   - Query activitiescache.db
   - Perform signature checks
   - Run generic checks
3. When finished, it will automatically open a `.txt` file containing the results

### 2. CLI Mode

1. Run the program from the command line
2. Provide one or two parameters:
   - The path where you want to save the data.
   - If you want to only save not digitally signed files, using `-n` or `--not-signed`.
3. Example: `ActivitesCacheExecution.exe C:\users\user\output.txt -n`
4. The program will perform all checks but won't automatically open the results file
