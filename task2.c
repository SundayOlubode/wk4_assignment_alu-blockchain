/* task2.c - Implementing Proof of Work */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

/* Constants */
#define MAX_TRANSACTIONS 10
#define HASH_SIZE 65
#define BLOCK_SIZE 1024

/* Structure definitions - same as task1.c */
typedef struct
{
        char data[256];
        time_t timestamp;
} Transaction;

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

/* Function prototypes */
void bytes_to_hex(unsigned char *bytes, char *hex, int size);
void calculate_block_hash(Block *block, char *output_hash);
Block *create_block(int index, const char *prev_hash);
int check_difficulty(const char *hash, int difficulty);
void mine_block(Block *block, int difficulty);

/* Functions from task1.c */
void bytes_to_hex(unsigned char *bytes, char *hex, int size)
{
        int i;
        for (i = 0; i < size; i++)
        {
                sprintf(&hex[i * 2], "%02x", bytes[i]);
        }
        hex[size * 2] = '\0';
}

void calculate_block_hash(Block *block, char *output_hash)
{
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;
        EVP_MD_CTX *ctx;
        char buffer[BLOCK_SIZE];
        int i;

        snprintf(buffer, sizeof(buffer), "%d%ld", block->index, block->timestamp);
        for (i = 0; i < block->transaction_count; i++)
        {
                strcat(buffer, block->transactions[i].data);
        }
        sprintf(buffer + strlen(buffer), "%s%lu", block->previous_hash, block->nonce);

        ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, buffer, strlen(buffer));
        EVP_DigestFinal_ex(ctx, hash, &hash_len);
        EVP_MD_CTX_free(ctx);

        bytes_to_hex(hash, output_hash, hash_len);
}

Block *create_block(int index, const char *prev_hash)
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
        memset(block->hash, 0, HASH_SIZE);
        block->next = NULL;

        return block;
}

/* New functions for Task 2 */
int check_difficulty(const char *hash, int difficulty)
{
        int i;
        for (i = 0; i < difficulty; i++)
        {
                if (hash[i] != '0')
                {
                        return 0;
                }
        }
        return 1;
}

void mine_block(Block *block, int difficulty)
{
        char temp_hash[HASH_SIZE];
        clock_t start, end;
        double cpu_time_used;
        unsigned long attempts = 0;

        printf("Mining block with difficulty %d...\n", difficulty);
        start = clock();

        do
        {
                calculate_block_hash(block, temp_hash);
                block->nonce++;
                attempts++;
        } while (!check_difficulty(temp_hash, difficulty));

        end = clock();
        cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

        strcpy(block->hash, temp_hash);

        printf("\nBlock mined!\n");
        printf("Nonce: %lu\n", block->nonce);
        printf("Hash: %s\n", block->hash);
        printf("Mining time: %.3f seconds\n", cpu_time_used);
        printf("Hash attempts: %lu\n", attempts);
        printf("Hashes per second: %.2f\n", attempts / cpu_time_used);
}

int main(void)
{
        Block *block;
        Transaction trans;
        char prev_hash[HASH_SIZE] = "0000000000000000000000000000000000000000000000000000000000000000";
        int difficulty = 4; /* Number of leading zeros required */

        printf("Task 2: Implementing Proof of Work\n\n");

        /* Create test block */
        block = create_block(0, prev_hash);
        if (!block)
        {
                printf("Failed to create block\n");
                return 1;
        }

        /* Add test transaction */
        strcpy(trans.data, "Test Transaction for Mining");
        trans.timestamp = time(NULL);
        block->transactions[0] = trans;
        block->transaction_count = 1;

        /* Mine the block */
        mine_block(block, difficulty);

        /* Clean up */
        free(block);
        return 0;
}