#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>

// # modes:
// # 0: insert, made up of 2 64 bit integers and a buffer. first int represents the starting index of the place to write to, the second int represents the length of the buffer, and the buffer contains the data to be written to the file.
// # 1: copy, made up of 3 64 bit integers. first int represents the starting index of the new file, the second represents the starting index of the original file, and the last int represents the length of the data to be copied from the original file to the new one.

// # the first 76 bytes are header data.
// # the first 4 bytes represents the version number of the format
// # the second 32 bytes represents the original files sha256 hash
// # the third 32 bytes represents the modified files sha256 hash
// # the last 8 bytes respesents a 64 bit unsigned integer of the length of the modified file

const uint32_t format_version_number = 100;

void read_to_buffer(FILE *file, char *digest, uint64_t length)
{
    for (uint64_t i = 0; i < length; i++)
    {
        digest[i] = fgetc(file);
    }
}

void compute_sha256(FILE *file, char digest[SHA256_DIGEST_LENGTH])
{
    fseek(file, 0, SEEK_SET);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        perror("EVP_MD_CTX_new");
        return;
    }

    const EVP_MD *md = EVP_sha256();

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1)
    {
        perror("EVP_DigestInit_ex");
        EVP_MD_CTX_free(ctx);
        return;
    }

    char buffer[SHA256_DIGEST_LENGTH];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, SHA256_DIGEST_LENGTH, file)) > 0)
    {
        if (EVP_DigestUpdate(ctx, buffer, bytesRead) != 1)
        {
            perror("EVP_DigestUpdate");
            EVP_MD_CTX_free(ctx);
            return;
        }
    }

    if (EVP_DigestFinal_ex(ctx, digest, NULL) != 1)
    {
        perror("EVP_DigestFinal_ex");
        EVP_MD_CTX_free(ctx);
        return;
    }

    EVP_MD_CTX_free(ctx);
}

void insert(FILE *diff, uint64_t starting_index, char *data, uint64_t length)
{
    if (length == 0)
        return;
    char mode = 0;
    fwrite(&mode, sizeof(char), 1, diff);
    fwrite(&starting_index, sizeof(uint64_t), 1, diff);
    fwrite(&length, sizeof(uint64_t), 1, diff);
    fwrite(data, sizeof(char), length, diff);
}

void copy(FILE *diff, uint64_t starting_index_new, uint64_t starting_index_original, uint64_t length)
{
    if (length == 0)
        return;
    char mode = 1;
    fwrite(&mode, sizeof(char), 1, diff);
    fwrite(&starting_index_new, sizeof(uint64_t), 1, diff);
    fwrite(&starting_index_original, sizeof(uint64_t), 1, diff);
    fwrite(&length, sizeof(uint64_t), 1, diff);
}

void create_diff_file(char original_file_path[], char modified_file_path[], char diff_file_path[], int reliance_level)
{
    FILE *original_file = fopen(original_file_path, "rb");
    FILE *modified_file = fopen(modified_file_path, "rb");
    FILE *diff_file = fopen(diff_file_path, "wb");

    uint64_t **byte_position_cache = malloc(256 * sizeof(uint64_t *));
    uint64_t *byte_position_length_cache = malloc(256 * sizeof(uint64_t));
    uint8_t *byte_position_written_to_cache = malloc(256 * sizeof(uint8_t));

    for (int i = 0; i < 256; i++)
    {
        byte_position_written_to_cache[i] = 0;
    }

    unsigned char original_hash[SHA256_DIGEST_LENGTH];
    compute_sha256(original_file, original_hash);

    unsigned char modified_hash[SHA256_DIGEST_LENGTH];
    compute_sha256(modified_file, modified_hash);

    fseek(modified_file, 0, SEEK_END);
    uint64_t modified_length = ftell(modified_file);

    fwrite(&format_version_number, sizeof(uint32_t), 1, diff_file);
    fwrite(original_hash, sizeof(unsigned char), SHA256_DIGEST_LENGTH, diff_file);
    fwrite(modified_hash, sizeof(unsigned char), SHA256_DIGEST_LENGTH, diff_file);
    fwrite(&modified_length, sizeof(uint64_t), 1, diff_file);

    uint64_t modified_cursor = 0;
    uint64_t last_index = 0;

    uint64_t iterations = 0;

    while (modified_cursor < modified_length)
    {
        if (iterations % 1000000 == 0)
        {
            printf("progress: %f%\n", ((double)modified_cursor / (double)modified_length) * 100);
        }
        iterations++;
        fseek(modified_file, modified_cursor, SEEK_SET);
        unsigned char first_byte = fgetc(modified_file);
        uint64_t first_bytes_from_original_file_length = 0;
        uint64_t *first_bytes_from_original_file = malloc((first_bytes_from_original_file_length + 1) * sizeof(uint64_t));
        if (!byte_position_written_to_cache[first_byte]) {
            fseek(original_file, 0, SEEK_SET);
            uint64_t index = 0;
            char original_byte;
            while ((original_byte = fgetc(original_file)) != EOF)
            {
                if (original_byte == first_byte)
                {
                    first_bytes_from_original_file = realloc(first_bytes_from_original_file, (first_bytes_from_original_file_length + 1) * sizeof(uint64_t));
                    first_bytes_from_original_file[first_bytes_from_original_file_length] = index;
                    first_bytes_from_original_file_length++;
                }
                index++;
            }
            // clone the first bytes from original file
            uint64_t *byte_position = malloc((first_bytes_from_original_file_length + 1) * sizeof(uint64_t));
            for (int i = 0; i < first_bytes_from_original_file_length; i++)
            {
                byte_position[i] = first_bytes_from_original_file[i];
            }
            byte_position_cache[first_byte] = byte_position;
            byte_position_length_cache[first_byte] = first_bytes_from_original_file_length;
            byte_position_written_to_cache[first_byte] = 1;
        } else {
            first_bytes_from_original_file = realloc(first_bytes_from_original_file, (byte_position_length_cache[first_byte] + 1) * sizeof(uint64_t));
            for (int i = 0; i < byte_position_length_cache[first_byte]; i++)
            {
                first_bytes_from_original_file[i] = byte_position_cache[first_byte][i];
            }
        }

        uint64_t length = 1;
        int found = 0;
        uint64_t first_byte_from_original = 0;
        char next_byte;
        while (first_bytes_from_original_file_length > 0 && (next_byte = fgetc(modified_file)) != EOF)
        {
            uint64_t temp_bytes_length = 0;
            uint64_t *temp_bytes = malloc((temp_bytes_length + 1) * sizeof(uint64_t));
            for (int i = 0; i < first_bytes_from_original_file_length; i++)
            {
                uint64_t index = first_bytes_from_original_file[i];
                fseek(original_file, index + length, SEEK_SET);
                char next_original_byte = fgetc(original_file);
                if (next_byte == next_original_byte)
                {
                    temp_bytes = realloc(temp_bytes, (temp_bytes_length + 1) * sizeof(uint64_t));
                    temp_bytes[temp_bytes_length] = index;
                    temp_bytes_length++;
                }
            }
            if (temp_bytes_length == 0)
            {
                break;
            }
            else
            {
                length++;
                free(first_bytes_from_original_file);
                first_bytes_from_original_file = temp_bytes;
                first_bytes_from_original_file_length = temp_bytes_length;
            }
        }
        if (first_bytes_from_original_file_length != 0)
        {
            found = 1;
            first_byte_from_original = first_bytes_from_original_file[0];
        }
        if (!found || length <= reliance_level)
        {
            modified_cursor++;
        }
        else
        {
            fseek(modified_file, last_index, SEEK_SET);
            char *modified_buffer = malloc((modified_cursor - last_index + 1)*sizeof(char));
            read_to_buffer(modified_file, modified_buffer, modified_cursor - last_index);
            insert(diff_file, last_index, modified_buffer, modified_cursor - last_index);
            free(modified_buffer);
            copy(diff_file, modified_cursor, first_byte_from_original, length);
            modified_cursor += length;
            last_index = modified_cursor;
        }
        free(first_bytes_from_original_file);
    }

    fseek(modified_file, last_index, SEEK_SET);
    char *modified_buffer = malloc(modified_length - last_index + 1);
    read_to_buffer(modified_file, modified_buffer, modified_length - last_index);
    insert(diff_file, last_index, modified_buffer, modified_length - last_index);
    free(modified_buffer);

    for (int i = 0; i < 256; i++)
    {
        if (byte_position_written_to_cache[i])
        {
            free(byte_position_cache[i]);
        }
    }
    free(byte_position_cache);
    free(byte_position_length_cache);
    free(byte_position_written_to_cache);

    fclose(original_file);
    fclose(modified_file);
    fclose(diff_file);
    return;
}

void apply_diff_file(char original_file_path[], char modified_file_path[], char diff_file_path[])
{
    FILE *original_file = fopen(original_file_path, "rb");
    FILE *modified_file = fopen(modified_file_path, "wb");
    FILE *diff_file = fopen(diff_file_path, "rb");

    uint32_t format_version_number;
    fread(&format_version_number, sizeof(uint32_t), 1, diff_file);
    unsigned char original_hash[SHA256_DIGEST_LENGTH];
    fread(original_hash, sizeof(unsigned char), SHA256_DIGEST_LENGTH, diff_file);
    unsigned char modified_hash[SHA256_DIGEST_LENGTH];
    fread(modified_hash, sizeof(unsigned char), SHA256_DIGEST_LENGTH, diff_file);
    uint64_t modified_length;
    fread(&modified_length, sizeof(uint64_t), 1, diff_file);

    unsigned char original_hash_computed[SHA256_DIGEST_LENGTH];
    compute_sha256(original_file, original_hash_computed);

    if (memcmp(original_hash, original_hash_computed, SHA256_DIGEST_LENGTH) != 0)
    {
        perror("original file hash does not match");
        return;
    }

    for (int i = 0; i < modified_length; i++)
    {
        fputc(0, modified_file);
    }

    char mode;

    while ((mode = fgetc(diff_file)) != EOF)
    {
        char *data;
        uint64_t length;
        switch (mode)
        {
        case 0:
            uint64_t starting_index;
            fread(&starting_index, sizeof(uint64_t), 1, diff_file);
            fread(&length, sizeof(uint64_t), 1, diff_file);
            data = malloc(length + 1);
            fread(data, sizeof(char), length, diff_file);
            fseek(modified_file, starting_index, SEEK_SET);
            fwrite(data, sizeof(char), length, modified_file);
            free(data);
            break;
        case 1:
            uint64_t starting_index_new;
            uint64_t starting_index_original;
            fread(&starting_index_new, sizeof(uint64_t), 1, diff_file);
            fread(&starting_index_original, sizeof(uint64_t), 1, diff_file);
            fread(&length, sizeof(uint64_t), 1, diff_file);
            data = malloc(length + 1);
            fseek(original_file, starting_index_original, SEEK_SET);
            fread(data, sizeof(char), length, original_file);
            fseek(modified_file, starting_index_new, SEEK_SET);
            fwrite(data, sizeof(char), length, modified_file);
            free(data);
            break;
        default:
            break;
        }
    }

    fclose(original_file);
    fclose(modified_file);
    fclose(diff_file);
    return;
}

int main()
{
    printf("start\n");
    create_diff_file("/home/william/Documents/Gorestorm.tar", "/home/william/Documents/Gorestorm_changes.tar", "diff_file.bin", 5);
    printf("created diff file\n");
    apply_diff_file("/home/william/Documents/Gorestorm.tar", "Gorestorm_changes.tar", "diff_file.bin");
    printf("done");
    return 0;
}