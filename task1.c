/* Task 1: Setting Up the Blockchain Environment */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

#define MAX_TRANSACTIONS 10
#define HASH_SIZE 65 /* SHA256 hex string (32 bytes * 2 chars + null) */
#define BLOCK_SIZE 1024

/* Transaction structure */
typedef struct
{
        char data[256];
        time_t timestamp;
} Transaction;

/* Block structure */
typedef struct Block
{
        int index;
        time_t timestamp;
        Transaction transactions[MAX_TRANSACTIONS];
        int transaction_count;
        char previous_hash[HASH_SIZE];
        char hash[HASH_SIZE];
        unsigned long nonce;
        struct Block *next;
} Block;

/* Convert bytes to hex string */
void bytes_to_hex(unsigned char *bytes, char *hex, int size)
{
        int i;
        for (i = 0; i < size; i++)
        {
                sprintf(&hex[i * 2], "%02x", bytes[i]);
        }
        hex[size * 2] = '\0';
}

/* Calculate block hash using SHA-256 */
void calculate_block_hash(Block *block, char *output_hash)
{
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;
        EVP_MD_CTX *ctx;
        char buffer[BLOCK_SIZE];
        int i;

        /* Concatenate block data */
        snprintf(buffer, sizeof(buffer), "%d%ld", block->index, block->timestamp);
        for (i = 0; i < block->transaction_count; i++)
        {
                strcat(buffer, block->transactions[i].data);
        }
        sprintf(buffer + strlen(buffer), "%s%lu", block->previous_hash, block->nonce);

        /* Calculate hash using EVP */
        ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, buffer, strlen(buffer));
        EVP_DigestFinal_ex(ctx, hash, &hash_len);
        EVP_MD_CTX_free(ctx);

        bytes_to_hex(hash, output_hash, hash_len);
}

/* Create a new block */
Block *create_block(int index, char *prev_hash)
{
        Block *block;

        block = (Block *)malloc(sizeof(Block));
        if (!block)
                return NULL;

        block->index = index;
        block->timestamp = time(NULL);
        block->transaction_count = 0;
        block->nonce = 0;
        strcpy(block->previous_hash, prev_hash);
        block->next = NULL;

        return block;
}

/* Test the blockchain setup */
int main(void)
{
        Block *block;
        Transaction trans;
        char prev_hash[HASH_SIZE] = "0000000000000000000000000000000000000000000000000000000000000000";

        /* Create a test block */
        block = create_block(0, prev_hash);
        if (!block)
        {
                printf("Failed to create block\n");
                return 1;
        }

        /* Add a test transaction */
        strcpy(trans.data, "Genesis Block Transaction");
        trans.timestamp = time(NULL);
        block->transactions[0] = trans;
        block->transaction_count = 1;

        /* Calculate and print block hash */
        calculate_block_hash(block, block->hash);

        printf("Block created successfully:\n");
        printf("Index: %d\n", block->index);
        printf("Timestamp: %ld\n", block->timestamp);
        printf("Transaction: %s\n", block->transactions[0].data);
        printf("Previous Hash: %s\n", block->previous_hash);
        printf("Hash: %s\n", block->hash);

        free(block);
        return 0;
}