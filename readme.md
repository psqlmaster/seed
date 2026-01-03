# BIP39 Seed Phrase Generator

This program generates valid BIP39 mnemonic seed phrases (12 or 24 words) using a provided wordlist (`BIP39.txt`). It is designed to create cryptographically secure seed phrases for use in cryptocurrency wallets, following the BIP39 standard.

## Features
- Generates BIP39-compliant seed phrases with 12 or 24 words.
- Supports specifying the number of successful seed phrases to generate.
- Uses the OpenSSL library for secure random number generation (`RAND_bytes`) and checksum computation (`SHA256`).
- Validates seed phrases to ensure correctness of the BIP39 checksum.
- Does not generate private keys or derive addresses, focusing solely on mnemonic generation.

## Dependencies
- **OpenSSL**: Required for cryptographic functions (`RAND_bytes` for entropy and `SHA256` for checksum).
  - Install on Ubuntu/Debian: `sudo apt install libssl-dev`
- **BIP39 Wordlist**: A file named `BIP39.txt` containing 2048 words in the format `index binary word`, where:
  - `index` is a number from 0 to 2047.
  - `binary` is an 11-bit binary representation of the index (e.g., `00000000000` for 0).
  - `word` is the corresponding BIP39 word (e.g., `abandon`).
  - Example lines:
    ```
    0 00000000000 abandon
    1 00000000001 ability
    2 00000000010 able
    ...
    2047 11111111111 zoo
    ```
  - The file must contain exactly 2048 lines and match the BIP39 English wordlist: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt (but formatted with indices and binary values).

## Compilation
To compile the program, ensure `BIP39.txt` is in the same directory as the source code (`seed.c`):

```bash
gcc -o seed seed.c -lssl -lcrypto
```

This links against the OpenSSL library (`-lssl -lcrypto`).

## Usage
Run the program with the following command-line options:

```bash
./seed [-c <count>] [-w <12|24>] [-h]
```

### Options
- `-c <count>`: Specifies the number of valid seed phrases to generate (default: 1). Must be a positive integer.
- `-w <12|24>`: Specifies the number of words in each seed phrase (12 or 24, default: 12).
  - 12 words: 128 bits of entropy + 4-bit checksum.
  - 24 words: 256 bits of entropy + 8-bit checksum.
- `-h`: Displays the help message with usage information.

### Examples
1. **Generate 20000 valid 24-word seed phrases**:
   ```bash
   ./seed -c 20000 -w 24
   ```
   Example output:
   ```
   File BIP39.txt opened
   Wordlist loaded: 2048 words
   Attempt 1 (successful: 0/2)
   Entropy generated (256 bits)
   SHA256 hash computed
   Entropy + checksum bits formed
   Seed phrase generated
   Seed phrase (BIP39, 24 words):
   category digital eye social engine injury this solid blade logic rabbit still tomato novel provide wide quality dove deer harbor leg unfold juice quote
   Validating seed phrase...
   Seed phrase is valid
   Attempt 2 (successful: 1/2)
   Entropy generated (256 bits)
   SHA256 hash computed
   Entropy + checksum bits formed
   Seed phrase generated
   Seed phrase (BIP39, 24 words):
   initial nature noise execute stuff miracle void front inhale fossil stand rifle grace hunt wreck kind cereal frown lesson chalk boil pond have village
   Validating seed phrase...
   Seed phrase is valid
   Memory cleaned up
   ```

2. **Generate 200 valid 12-word seed phrases**:
   ```bash
   ./seed -c 200 -w 12
   ```
   Output will include up to 200 valid seed phrases, each with 12 words, following the same format as above.

3. **Display help message**:
   ```bash
   ./seed -h
   ```
   Output:
   ```
   Usage: ./seed [-c <count>] [-w <12|24>] [-h]
   Options:
     -c <count>     Number of successful seed phrases to generate (default: 1)
     -w <12|24>     Number of words in seed phrase (12 or 24, default: 12)
     -h             Display this help message
   ```

## How It Works
1. **Wordlist Loading**:
   - Reads `BIP39.txt`, expecting 2048 lines in the format `index binary word` (e.g., `0 00000000000 abandon`).
   - Validates the index (0 to 2047), binary representation, and word for each line.
   - Ensures exactly 2048 words are loaded.

2. **Seed Phrase Generation**:
   - Generates random entropy using `RAND_bytes`:
     - 128 bits for 12-word phrases.
     - 256 bits for 24-word phrases.
   - Computes a SHA256 hash of the entropy to derive a checksum (4 bits for 12 words, 8 bits for 24 words).
   - Combines entropy and checksum into a bit array.
   - Splits the bit array into 11-bit groups, each mapping to an index (0–2047) in the wordlist.
   - Constructs the mnemonic phrase by selecting words corresponding to these indices.

3. **Validation**:
   - Verifies that each generated phrase contains valid BIP39 words from the wordlist.
   - Reconstructs the entropy and checksum from the phrase.
   - Recomputes the SHA256 hash of the entropy and checks if the checksum matches.
   - Invalid phrases (e.g., with incorrect checksums) are silently discarded, and generation continues until the requested number of valid phrases is produced.

4. **Output**:
   - Displays each attempt with entropy generation, hash computation, and the resulting seed phrase.
   - Only valid seed phrases are shown, with a maximum of 100 attempts per requested phrase to prevent infinite loops.

## Notes
- **Security**: This is an educational tool. For production use:
  - Ensure seed phrases are stored securely (never in plain text).
  - Use a cryptographically secure environment for generation.
- **Word Repetition**: Words in a single seed phrase may repeat (with a low probability, ~3.5% for 12 words, higher for 24 words), as allowed by BIP39. This does not affect security, as entropy is provided by the random bits.
- **Unique Phrases**: The probability of generating identical seed phrases is negligible (2^128 for 12 words, 2^256 for 24 words).
- **BIP39 Standard**: The generated seed phrases are compatible with any BIP39-compliant wallet and can be used with standards like BIP32, BIP44, BIP49, BIP84, or BIP141 for key derivation (not implemented in this program).

## Verification
To verify generated seed phrases:
1. Copy a seed phrase from the output.
2. Paste it into a BIP39-compatible tool, such as https://iancoleman.io/bip39/.
3. Ensure the tool accepts the phrase without an "Invalid mnemonic" error.

## Troubleshooting
1. **Incorrect `BIP39.txt` Format**:
   - Ensure `BIP39.txt` has 2048 lines in the format `index binary word`:
     ```
     0 00000000000 abandon
     1 00000000001 ability
     ...
     2047 11111111111 zoo
     ```
   - Verify the file has exactly 2048 lines:
     ```bash
     wc -l BIP39.txt
     ```
   - If the format is incorrect, create a new `BIP39.txt` by adding indices and binary representations to the official BIP39 wordlist: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

2. **Compilation Issues**:
   - Ensure OpenSSL is installed:
     ```bash
     sudo apt install libssl-dev
     ```
   - Check OpenSSL version:
     ```bash
     openssl version
     ```
   - Verify dependencies:
     ```bash
     ldd ./seed
     ```


