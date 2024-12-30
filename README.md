# Memory Forensics Tool

A Python-based tool for performing basic memory forensics tasks, including capturing memory dumps, analyzing processes, detecting malicious patterns, and extracting artifacts.

## Features

- **Capture Memory Dumps**: Simulates capturing active memory data from running processes.
- **Process Inspection**: Lists active processes with details like PID, name, memory usage, and user.
- **Malicious Pattern Detection**: Identifies suspicious processes based on regex patterns.
- **Artifact Extraction**: Extracts relevant artifacts (e.g., browser session information) from memory dumps.

## Learning Objectives

- Gain hands-on experience in digital forensics and memory analysis.
- Develop skills in process inspection and handling memory dumps.

## Skills Developed

- Digital forensics and memory analysis
- Python programming for system and process analysis

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/4LPH7/MemScope.git
   cd MemScope
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the tool:
   ```bash
   python memory_forensics_tool.py
   ```

2. Follow the on-screen instructions to capture memory dumps, analyze processes, and perform other tasks.

## Example Output

```
[INFO] Memory Forensics Tool
[INFO] Capturing memory dump...
[INFO] Memory dump saved to memory_dump.txt
[INFO] Analyzing running processes...
PID: 1234, Name: python.exe, Memory: 1048576, User: user
[INFO] Detecting malicious patterns...
[ALERT] Suspicious Processes Detected:
PID: 5678, Name: malware.exe
[INFO] Extracting artifacts...
[INFO] Extracted Artifacts:
{'pid': 1234, 'name': 'browser.exe', 'artifact': 'Possible browser session'}
```

## Requirements

- Python 3.8+
- Libraries:
  - psutil
  - re
  - json
  - datetime

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for review.

---

## Author

Developed by [ARUL G](https://github.com/4LPH7).

## Acknowledgements

- Inspired by Volatility and other memory forensics tools.
- Thanks to the Python community for excellent libraries and support.

## Disclaimer

This tool is intended for educational purposes only. Use responsibly and ensure compliance with applicable laws and regulations.
