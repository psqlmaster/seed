#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Constants
#define WORDLIST_SIZE 2048
#define MAX_WORD_LEN 20
#define MAX_LINE_LEN 50

// Load BIP39 wordlist from file
char **load_bip39_wordlist(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error opening file %s\n", filename);
        exit(1);
    }
    printf("File %s opened\n", filename);

    char **wordlist = calloc(WORDLIST_SIZE, sizeof(char *));
    if (!wordlist) {
        fprintf(stderr, "Error allocating memory for wordlist\n");
        fclose(file);
        exit(1);
    }

    char line[MAX_LINE_LEN];
    int index = 0;
    while (fgets(line, MAX_LINE_LEN, file) && index < WORDLIST_SIZE) {
        int idx;
        char binary[12], word[MAX_WORD_LEN];
        if (sscanf(line, "%d %11s %s", &idx, binary, word) != 3) {
            fprintf(stderr, "Error parsing line %d: %s\n", index + 1, line);
            fclose(file);
            exit(1);
        }
        if (idx != index) {
            fprintf(stderr, "Invalid index at line %d: expected %d, got %d\n", index + 1, index, idx);
            fclose(file);
            exit(1);
        }
        wordlist[index] = strdup(word);
        if (!wordlist[index]) {
            fprintf(stderr, "Error allocating memory for word %d\n", index);
            fclose(file);
            exit(1);
        }
        index++;
    }
    if (index != WORDLIST_SIZE) {
        fprintf(stderr, "Error: expected %d words, found %d\n", WORDLIST_SIZE, index);
        fclose(file);
        exit(1);
    }
    fclose(file);
    printf("Wordlist loaded: %d words\n", WORDLIST_SIZE);
    return wordlist;
}

// Free wordlist memory
void free_bip39_wordlist(char **wordlist) {
    for (int i = 0; i < WORDLIST_SIZE; i++) {
        free(wordlist[i]);
    }
    free(wordlist);
}

// Validate BIP39 mnemonic (silently skip invalid checksums)
int validate_mnemonic(const char *mnemonic, char **wordlist, int word_count) {
    char *mnemonic_copy = strdup(mnemonic);
    if (!mnemonic_copy) {
        return 0;
    }

    // Split mnemonic into words
    char *words[24];
    int actual_count = 0;
    char *token = strtok(mnemonic_copy, " ");
    while (token && actual_count < 24) {
        words[actual_count++] = token;
        token = strtok(NULL, " ");
    }
    if (actual_count != word_count) {
        free(mnemonic_copy);
        return 0;
    }

    // Get word indices
    unsigned int indices[24];
    for (int i = 0; i < word_count; i++) {
        int found = 0;
        for (int j = 0; j < WORDLIST_SIZE; j++) {
            if (strcmp(words[i], wordlist[j]) == 0) {
                indices[i] = j;
                found = 1;
                break;
            }
        }
        if (!found) {
            free(mnemonic_copy);
            return 0;
        }
    }

    // Reconstruct bits
    int entropy_bits = (word_count == 12) ? 128 : 256;
    int checksum_bits = entropy_bits / 32;
    int total_bits = entropy_bits + checksum_bits;
    int byte_count = (total_bits + 7) / 8;
    unsigned char bits[33] = {0};
    for (int i = 0; i < word_count; i++) {
        for (int j = 0; j < 11; j++) {
            int bit_idx = i * 11 + j;
            int byte_idx = bit_idx / 8;
            int bit_pos = 7 - (bit_idx % 8);
            if (indices[i] & (1 << (10 - j))) {
                bits[byte_idx] |= (1 << bit_pos);
            }
        }
    }

    // Verify checksum
    unsigned char entropy[32];
    memcpy(entropy, bits, entropy_bits / 8);
    unsigned char hash[32];
    SHA256(entropy, entropy_bits / 8, hash);
    unsigned char expected_checksum = hash[0] >> (8 - checksum_bits);
    unsigned char actual_checksum = bits[byte_count - 1] & ((1 << checksum_bits) - 1);

    free(mnemonic_copy);
    if (expected_checksum != actual_checksum) {
        return 0;
    }
    printf("Seed phrase is valid\n");
    return 1;
}

// Generate BIP39 mnemonic (12 or 24 words)
void generate_mnemonic(char *mnemonic, size_t len, char **wordlist, int word_count) {
    int entropy_bits = (word_count == 12) ? 128 : 256;
    int checksum_bits = entropy_bits / 32;
    int total_bits = entropy_bits + checksum_bits;
    int byte_count = (total_bits + 7) / 8;

    unsigned char entropy[32];
    if (RAND_bytes(entropy, entropy_bits / 8) != 1) {
        fprintf(stderr, "Error generating entropy\n");
        exit(1);
    }
    printf("Entropy generated (%d bits)\n", entropy_bits);

    unsigned char hash[32];
    SHA256(entropy, entropy_bits / 8, hash);
    printf("SHA256 hash computed\n");

    // Form bits (entropy + checksum)
    unsigned char bits[33] = {0};
    memcpy(bits, entropy, entropy_bits / 8);
    bits[byte_count - 1] = hash[0] >> (8 - checksum_bits);
    printf("Entropy + checksum bits formed\n");

    memset(mnemonic, 0, len);
    size_t offset = 0;
    for (int i = 0; i < word_count; i++) {
        unsigned int word_index = 0;
        for (int j = 0; j < 11; j++) {
            int bit_idx = i * 11 + j;
            int byte_idx = bit_idx / 8;
            int bit_pos = 7 - (bit_idx % 8);
            word_index |= ((bits[byte_idx] >> bit_pos) & 1) << (10 - j);
        }
        if (word_index >= WORDLIST_SIZE || wordlist[word_index] == NULL) {
            fprintf(stderr, "Error: invalid word index %d\n", word_index);
            exit(1);
        }
        size_t word_len = strlen(wordlist[word_index]);
        if (offset + word_len + 2 > len) {
            fprintf(stderr, "Error: insufficient buffer space for mnemonic (offset=%zu, word_len=%zu)\n", offset, word_len);
            exit(1);
        }
        int written = snprintf(mnemonic + offset, len - offset, "%s%s", wordlist[word_index], i < word_count - 1 ? " " : "");
        if (written < 0 || (size_t)written >= len - offset) {
            fprintf(stderr, "Error writing word %d\n", i + 1);
            exit(1);
        }
        offset += written;
    }
    printf("Seed phrase generated\n");
}

// Display help message
void print_help(const char *prog_name) {
    printf("Usage: %s [-c <count>] [-w <12|24>] [-h]\n", prog_name);
    printf("Options:\n");
    printf("  -c <count>     Number of successful seed phrases to generate (default: 1)\n");
    printf("  -w <12|24>     Number of words in seed phrase (12 or 24, default: 12)\n");
    printf("  -h             Display this help message\n");
}

int main(int argc, char *argv[]) {
    // Parse command-line arguments
    int success_count = 1; // Default: 1 iteration
    int word_count = 12;   // Default: 12 words
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            success_count = atoi(argv[i + 1]);
            if (success_count <= 0) {
                fprintf(stderr, "Error: -c must be a positive number\n");
                return 1;
            }
            i++;
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            word_count = atoi(argv[i + 1]);
            if (word_count != 12 && word_count != 24) {
                fprintf(stderr, "Error: -w must be 12 or 24\n");
                return 1;
            }
            i++;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_help(argv[0]);
            return 1;
        }
    }

    // Load wordlist
    char **wordlist = load_bip39_wordlist("BIP39.txt");

    // Generate specified number of valid seed phrases
    char mnemonic[600]; // Increased buffer for 24 words
    int successful = 0;
    int attempts = 0;
    while (successful < success_count && attempts < 100 * success_count) {
        attempts++;
        printf("Attempt %d (successful: %d/%d)\n", attempts, successful, success_count);
        generate_mnemonic(mnemonic, sizeof(mnemonic), wordlist, word_count);
        printf("Seed phrase (BIP39, %d words):\n%s\n\n", word_count, mnemonic);
        printf("Validating seed phrase...\n");
        if (validate_mnemonic(mnemonic, wordlist, word_count)) {
            successful++;
        }
    }

    if (successful < success_count) {
        fprintf(stderr, "Failed to generate %d valid seed phrases after %d attempts\n", success_count, attempts);
        free_bip39_wordlist(wordlist);
        return 1;
    }

    // Clean up
    free_bip39_wordlist(wordlist);
    printf("Memory cleaned up\n");
    return 0;
}
