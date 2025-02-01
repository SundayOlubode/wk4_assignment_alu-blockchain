/* task3.c - Mining a Block */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

/* Constants */
#define MAX_TRANSACTIONS 10
#define HASH_SIZE 65
#define BLOCK_SIZE 1024

/* Structure definitions */
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

typedef struct
{
        Block *head;
        int length;
} Blockchain;

/* Function prototypes */
void bytes_to_hex(unsigned char *bytes, char *hex, int size);
void calculate_block_hash(Block *block, char *output_hash);
Block *create_block(int index, const char *prev_hash);
int check_difficulty(const char *hash, int difficulty);
void mine_block(Block *block, int difficulty);
Blockchain *create_blockchain(void);
void add_block(Blockchain *chain, Block *block);
int verify_blockchain(Blockchain *chain);
Block *create_and_mine_block(Blockchain *chain, Transaction *transactions,
                             int transaction_count, int difficulty);
void cleanup_blockchain(Blockchain *chain);

/* Functions from previous tasks */
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

/* Create a new block */
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

/* Check if hash meets difficulty requirement */
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

/* Mine a block */
void mine_block(Block *block, int difficulty)
{
        char temp_hash[HASH_SIZE];
        clock_t start, end;
        double cpu_time_used;

        printf("Mining block with difficulty %d...\n", difficulty);
        start = clock();

        do
        {
                calculate_block_hash(block, temp_hash);
                block->nonce++;
        } while (!check_difficulty(temp_hash, difficulty));

        end = clock();
        cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;

        strcpy(block->hash, temp_hash);

        printf("\nBlock mined!\n");
        printf("Hash: %s\n", block->hash);
        printf("Nonce: %lu\n", block->nonce);
        printf("Mining time: %.3f seconds\n", cpu_time_used);
}

/* Initialize blockchain */
Blockchain *create_blockchain(void)
{
        Blockchain *chain;

        chain = (Blockchain *)malloc(sizeof(Blockchain));
        if (!chain)
                return NULL;

        chain->head = NULL;
        chain->length = 0;
        return chain;
}

/* Add block to blockchain */
void add_block(Blockchain *chain, Block *block)
{
        if (chain->head != NULL)
        {
                block->next = chain->head;
        }
        chain->head = block;
        chain->length++;
}

/* Verify blockchain integrity */
int verify_blockchain(Blockchain *chain)
{
        Block *current;
        char calculated_hash[HASH_SIZE];

        if (!chain->head)
                return 1;

        current = chain->head;
        while (current->next != NULL)
        {
                calculate_block_hash(current, calculated_hash);
                if (strcmp(calculated_hash, current->hash) != 0)
                {
                        return 0;
                }

                if (strcmp(current->previous_hash, current->next->hash) != 0)
                {
                        return 0;
                }

                current = current->next;
        }

        return 1;
}

/* Create and mine a new block */
Block *create_and_mine_block(Blockchain *chain, Transaction *transactions,
                             int transaction_count, int difficulty)
{
        Block *new_block;
        char prev_hash[HASH_SIZE];
        int i;

        if (chain->head != NULL)
        {
                strcpy(prev_hash, chain->head->hash);
        }
        else
        {
                strcpy(prev_hash, "0000000000000000000000000000000000000000000000000000000000000000");
        }

        new_block = create_block(chain->length, prev_hash);
        if (!new_block)
                return NULL;

        for (i = 0; i < transaction_count && i < MAX_TRANSACTIONS; i++)
        {
                new_block->transactions[i] = transactions[i];
        }
        new_block->transaction_count = transaction_count;

        mine_block(new_block, difficulty);
        return new_block;
}

/* Clean up blockchain */
void cleanup_blockchain(Blockchain *chain)
{
        Block *current;
        Block *next;

        if (!chain)
                return;

        current = chain->head;
        while (current != NULL)
        {
                next = current->next;
                free(current);
                current = next;
        }

        free(chain);
}

/* Print block details */
void print_block(Block *block)
{
        int i;

        printf("\nBlock %d:\n", block->index);
        printf("Timestamp: %ld\n", block->timestamp);
        printf("Transactions:\n");
        for (i = 0; i < block->transaction_count; i++)
        {
                printf("  %s\n", block->transactions[i].data);
        }
        printf("Previous Hash: %s\n", block->previous_hash);
        printf("Hash: %s\n", block->hash);
        printf("Nonce: %lu\n", block->nonce);
}

int main(void)
{
        Blockchain *chain;
        Block *new_block;
        Transaction transactions[2];
        int difficulty = 3;

        printf("Task 3: Mining a Block\n\n");

        /* Initialize blockchain */
        chain = create_blockchain();
        if (!chain)
        {
                printf("Failed to create blockchain\n");
                return 1;
        }

        /* Create test transactions */
        strcpy(transactions[0].data, "Alice sends 50 BTC to Bob");
        transactions[0].timestamp = time(NULL);
        strcpy(transactions[1].data, "Bob sends 30 BTC to Charlie");
        transactions[1].timestamp = time(NULL);

        /* Mine and add first block */
        printf("\nMining first block...\n");
        new_block = create_and_mine_block(chain, &transactions[0], 1, difficulty);
        if (!new_block)
        {
                printf("Failed to create block\n");
                cleanup_blockchain(chain);
                return 1;
        }
        add_block(chain, new_block);

        /* Mine and add second block */
        printf("\nMining second block...\n");
        new_block = create_and_mine_block(chain, &transactions[1], 1, difficulty);
        if (!new_block)
        {
                printf("Failed to create block\n");
                cleanup_blockchain(chain);
                return 1;
        }
        add_block(chain, new_block);

        /* Verify blockchain */
        printf("\nBlockchain verification: %s\n",
               verify_blockchain(chain) ? "SUCCESS" : "FAILED");

        /* Print all blocks */
        printf("\nFinal blockchain state:\n");
        new_block = chain->head;
        while (new_block != NULL)
        {
                print_block(new_block);
                new_block = new_block->next;
        }

        /* Clean up */
        cleanup_blockchain(chain);

        return 0;
}