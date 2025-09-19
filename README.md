# Lightweight File Encryption System

This project provides a simple command-line and graphical tool for encrypting and decrypting files using the Data Encryption Standard (DES) algorithm. It is designed as a lightweight system for securing files, such as the example `student_records.csv`, at Federal University Dutse.

The script uses a robust cryptographic structure, deriving an encryption key from a user-provided passphrase using PBKDF2 and ensuring file integrity with an HMAC-SHA256 signature.

## Features

- **File Encryption & Decryption**: Securely encrypt and decrypt any file.
- **Strong Key Derivation**: Uses PBKDF2 with 200,000 iterations to protect against brute-force attacks on the passphrase.
- **Data Integrity**: Employs HMAC-SHA256 to ensure that encrypted files have not been tampered with.
- **Dual Interface**:
  - A simple command-line interface (CLI) for scripting and terminal use.
  - A user-friendly graphical user interface (GUI) for ease of use.
- **Cross-Platform**: Written in Python, compatible with macOS, Windows, and Linux.

## Requirements

- Python 3.x
- `pycryptodome` library

## Setup and Installation

1.  **Clone the repository or download the source code.**

2.  **Create and activate a virtual environment.** This is highly recommended to keep project dependencies isolated.

    ```sh
    # Create the virtual environment
    python3 -m venv venv

    # Activate it (on macOS/Linux)
    source venv/bin/activate

    # On Windows, use:
    # venv\Scripts\activate
    ```

3.  **Install the required dependencies** from the `requirements.txt` file.

    ```sh
    pip install -r requirements.txt
    ```

    _Note: The GUI requires Tkinter, which is included with most Python installations on Windows and macOS. On some Linux distributions, you may need to install it separately (e.g., `sudo apt-get install python3-tk`)._

## Usage

You can interact with the tool via the command line or the graphical interface.

### Graphical User Interface (GUI)

To launch the GUI, run the following command in your terminal:

```sh
python script.py gui
```

The interface allows you to:

1.  Browse for an input file.
2.  Enter a passphrase.
3.  Click **Encrypt** or **Decrypt**.
4.  Choose a location to save the output file.

  <!-- Placeholder for a screenshot -->

### Command-Line Interface (CLI)

#### To Encrypt a File

```sh
python script.py encrypt [input_file]
```

Example:

```sh
python script.py encrypt student_records.csv
```

The script will prompt you to enter a passphrase. An encrypted file named `student_records.csv.enc` will be created.

#### To Decrypt a File

```sh
python script.py decrypt [encrypted_file]
```

Example:

```sh
python script.py decrypt student_records.csv.enc
```

The script will prompt for the passphrase and create a decrypted file named `student_records.csv`.

#### CLI Options

- `-o, --output`: Specify a custom name for the output file.
- `-p, --passphrase`: Provide the passphrase directly as an argument (less secure).

## Security Disclaimer

This project uses the **Data Encryption Standard (DES)**, which has a small 56-bit key size. DES is considered cryptographically weak and is vulnerable to modern brute-force attacks. This tool is intended for educational purposes to demonstrate cryptographic principles and should **not** be used to protect highly sensitive data. For robust security, use modern algorithms like AES-256.
