# hasher

hasher.py is a python script used for mobile device acquisition triage. 
It lists all files with their simple name, size, sha256 and md5 hashes.
It also lists the file path and file type for applicable files.

### 2.0.1 updates include:
- Pass in a csv file to --type or --hash and have it filter for scanning or reading.
- Refactored code for easier readability.
- Added more unitests.

## Future updates will include:
- Storing X most recent reports 


### Installation

#### Linux
- Open up command line.
 - `git clone https://github.com/PuzzleZach/hasher.git`
 - Move folder to desired directory with `mv` command.
- `pip3 install pathlib`

#### Windows
- Download ZIP
- Unpack in directory you want to run
- `pip3 install pathlib`

### Running
`./hasher.py path [-r] [-o {csv}] [--type {file type}] [--hash {md5 or sha}]`

- **Path** is the file path for either scanning a directory or reading a previous report.
- **r** is a switch for reading from the path.
- **o** is a switch for scanning the path. Output will be a csv file.
- **--type** for added filtering, you can only read or scan a certain file type (png, txt, etc).
- **--hash** like type, you can filter a specific hash when searching a report or directory.

### Testing

Current build passes 6/6 tests for -r mode. Tests could be added for the scanning mode.
