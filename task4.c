/* task4.c - Adjusting Blockchain Difficulty */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

/* Constants */
#define MAX_TRANSACTIONS 10
#define HASH_SIZE 65
#define BLOCK_SIZE 1024
#define MAX_DIFFICULTY 5

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
        int difficulty;
} Blockchain;

/* Mining metrics structure */
typedef struct
{
        double mining_time;
        unsigned long nonce_attempts;
        int difficulty;
        double hash_rate;
} MiningMetrics;

/* Function prototypes */
void bytes_to_hex(unsigned char *bytes, char *hex, int size);
void calculate_block_hash(Block *block, char *output_hash);
Block *create_block(int index, const char *prev_hash);
int check_difficulty(const char *hash, int difficulty);
Blockchain *create_blockchain(int difficulty);
MiningMetrics mine_block_with_metrics(Block *block, int difficulty);
Block *create_and_mine_block(Blockchain *chain, Transaction *transactions, int count);
void cleanup_blockchain(Blockchain *chain);
void print_mining_metrics(MiningMetrics metrics);

/* Previous functions implementation */
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

/* New implementation for Task 4 */
Blockchain *create_blockchain(int difficulty)
{
        Blockchain *chain;

        chain = (Blockchain *)malloc(sizeof(Blockchain));
        if (!chain)
                return NULL;

        chain->head = NULL;
        chain->length = 0;
        chain->difficulty = difficulty;
        return chain;
}

MiningMetrics mine_block_with_metrics(Block *block, int difficulty)
{
        MiningMetrics metrics;
        char temp_hash[HASH_SIZE];
        clock_t start, end;

        metrics.difficulty = difficulty;
        metrics.nonce_attempts = 0;
        block->nonce = 0;

        start = clock();

        do
        {
                calculate_block_hash(block, temp_hash);
                block->nonce++;
                metrics.nonce_attempts++;
        } while (!check_difficulty(temp_hash, difficulty));

        end = clock();
        metrics.mining_time = ((double)(end - start)) / CLOCKS_PER_SEC;
        metrics.hash_rate = metrics.nonce_attempts / metrics.mining_time;

        strcpy(block->hash, temp_hash);

        return metrics;
}

void print_mining_metrics(MiningMetrics metrics)
{
        printf("\nMining Metrics:\n");
        printf("Difficulty: %d\n", metrics.difficulty);
        printf("Time taken: %.3f seconds\n", metrics.mining_time);
        printf("Nonce attempts: %lu\n", metrics.nonce_attempts);
        printf("Hash rate: %.2f hashes/second\n", metrics.hash_rate);
        printf("Average attempts per leading zero: %.2f\n",
               (double)metrics.nonce_attempts / metrics.difficulty);
}

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

Block *create_and_mine_block(Blockchain *chain, Transaction *transactions, int count)
{
        Block *new_block;
        char prev_hash[HASH_SIZE];
        MiningMetrics metrics;
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

        for (i = 0; i < count && i < MAX_TRANSACTIONS; i++)
        {
                new_block->transactions[i] = transactions[i];
        }
        new_block->transaction_count = count;

        metrics = mine_block_with_metrics(new_block, chain->difficulty);
        print_mining_metrics(metrics);

        return new_block;
}

int main(void)
{
        Blockchain *chain;
        Block *new_block;
        Transaction transaction;
        MiningMetrics total_metrics[MAX_DIFFICULTY];
        int difficulty;
        int i;

        printf("Task 4: Adjusting Blockchain Difficulty\n\n");
        printf("Testing mining performance with different difficulties...\n");

        /* Test each difficulty level */
        for (difficulty = 1; difficulty <= MAX_DIFFICULTY; difficulty++)
        {
                printf("\n=== Testing difficulty %d ===\n", difficulty);

                /* Create new blockchain with current difficulty */
                chain = create_blockchain(difficulty);
                if (!chain)
                {
                        printf("Failed to create blockchain\n");
                        return 1;
                }

                /* Create test transaction */
                strcpy(transaction.data, "Test Transaction");
                transaction.timestamp = time(NULL);

                /* Mine block and collect metrics */
                new_block = create_and_mine_block(chain, &transaction, 1);
                if (!new_block)
                {
                        printf("Failed to create block\n");
                        cleanup_blockchain(chain);
                        continue;
                }

                /* Store metrics for comparison */
                total_metrics[difficulty - 1] = mine_block_with_metrics(new_block, difficulty);

                cleanup_blockchain(chain);
        }

        /* Print comparative analysis */
        printf("\n=== Mining Performance Analysis ===\n");
        for (i = 0; i < MAX_DIFFICULTY; i++)
        {
                printf("\nDifficulty %d:\n", i + 1);
                printf("Time taken: %.3f seconds\n", total_metrics[i].mining_time);
                printf("Nonce attempts: %lu\n", total_metrics[i].nonce_attempts);
                printf("Hash rate: %.2f hashes/second\n", total_metrics[i].hash_rate);

                if (i > 0)
                {
                        printf("Time increase from previous difficulty: %.2fx\n",
                               total_metrics[i].mining_time / total_metrics[i - 1].mining_time);
                        printf("Nonce attempts increase: %.2fx\n",
                               (double)total_metrics[i].nonce_attempts / total_metrics[i - 1].nonce_attempts);
                }
        }

        return 0;
}