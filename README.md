# abugo

A simple command-line tool written in Go to unpack Android Backup (`.ab`) files.

This tool is designed to extract the contents of backups created using Android Debug Bridge (ADB), supporting various backup versions, compression, and encryption.

## Features

*   Unpacks Android Backup (`.ab`) files into standard TAR archives.
*   Supports Android backup versions V1 through V5.
*   Handles zlib compression automatically if present.
*   Decrypts backups encrypted with AES-256 (requires the correct password).
*   Accepts password input via command-line argument or the `ABUGO_PASSWD` environment variable.
*   Can read backup data from a file or standard input (stdin).
*   Can write the extracted TAR archive to a file or standard output (stdout).

## Building

Ensure you have Go installed (version 1.18 or later recommended).

```bash
# Clone the repository (if you haven't already)
# git clone <repository_url>
# cd abugo

# Build the executable
go build .
```

This will create an executable named `abugo` (or `abugo.exe` on Windows) in the current directory.

## Usage

The primary command is `unpack`:

```
./abugo unpack <input.ab> <output.tar> [password]
```

**Arguments:**

*   `<input.ab>`: Path to the Android backup file (`.ab`). Use `-` to read from standard input (stdin).
*   `<output.tar>`: Path where the extracted TAR archive will be written. Use `-` to write to standard output (stdout).
*   `[password]`: (Optional) The password for decrypting an encrypted backup.

**Password Handling:**

If the backup is encrypted:

1.  You can provide the password directly as the last command-line argument.
2.  If the password argument is omitted, `abugo` will check for the `ABUGO_PASSWD` environment variable and use its value if set.
3.  If the backup is encrypted and no password is provided via argument or environment variable, the tool will exit with an error.

## Examples

**1. Unpack an unencrypted backup file:**

```bash
./abugo unpack my_backup.ab my_backup.tar
```

**2. Unpack an encrypted backup file (password as argument):**

```bash
./abugo unpack secure_backup.ab secure_backup.tar mySecretPassword123
```

**3. Unpack an encrypted backup file (password via environment variable):**

```bash
export ABUGO_PASSWD="mySecretPassword123"
./abugo unpack secure_backup.ab secure_backup.tar
# Unset the variable afterwards if desired
unset ABUGO_PASSWD
```

**4. Unpack from stdin to stdout (e.g., piping directly from ADB):**

```bash
# Make sure to provide the password if the backup is encrypted
adb backup -f - com.example.app | ./abugo unpack - backup.tar [your_password_here_if_needed]
```

**5. Unpack from a file to stdout (e.g., piping to `tar` command):**

```bash
./abugo unpack my_backup.ab - [your_password_here_if_needed] | tar tvf -
```