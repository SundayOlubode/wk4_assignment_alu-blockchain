#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

/* Constants for blockchain configuration */
#define MAX_TRANSACTIONS 10
#define HASH_SIZE 65 /* SHA256 hex string (32 bytes * 2 chars + null) */
#define MAX_DIFFICULTY 4
#define BLOCK_SIZE 1024

/**
 * struct Transaction - Structure to store transaction data
 * @data: string containing transaction details
 * @timestamp: time when transaction was created
 *
 * Description: Represents a single transaction in the blockchain
 */
typedef struct
{
        char data[256];
        time_t timestamp;
} Transaction;

/**
 * struct Block - Structure for blockchain block
 * @index: position of block in chain
 * @timestamp: time when block was created
 * @transactions: array of transactions in block
 * @transaction_count: number of transactions in block
 * @previous_hash: hash of previous block
 * @hash: hash of current block
 * @nonce: value used in proof-of-work
 * @next: pointer to next block
 *
 * Description: Represents a block in the blockchain
 */
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

/**
 * struct Blockchain - Structure for managing blockchain
 * @head: pointer to first block
 * @difficulty: current mining difficulty
 * @length: number of blocks in chain
 *
 * Description: Main structure for blockchain management
 */
typedef struct
{
        Block *head;
        int difficulty;
        int length;
} Blockchain;

/**
 * bytes_to_hex - Convert byte array to hexadecimal string
 * @bytes: input byte array
 * @hex: output hexadecimal string
 * @size: size of byte array
 *
 * Description: Converts a byte array to its hexadecimal string representation
 * Return: void
 */
void bytes_to_hex(unsigned char *bytes, char *hex, int size)
{
        int i;

        for (i = 0; i < size; i++)
        {
                sprintf(&hex[i * 2], "%02x", bytes[i]);
        }
        hex[size * 2] = '\0';
}

/**
 * calculate_block_hash - Calculate SHA-256 hash for a block
 * @block: pointer to block structure
 * @output_hash: buffer to store resulting hash
 *
 * Description: Generates SHA-256 hash of block data including transactions
 * Return: void
 */
void calculate_block_hash(Block *block, char *output_hash)
{
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;
        EVP_MD_CTX *ctx;
        char buffer[BLOCK_SIZE];
        int i;

        /* Concatenate block data for hashing */
        snprintf(buffer, sizeof(buffer), "%d%ld", block->index, block->timestamp);

        /* Add all transactions */
        for (i = 0; i < block->transaction_count; i++)
        {
                strcat(buffer, block->transactions[i].data);
        }

        sprintf(buffer + strlen(buffer), "%s%lu", block->previous_hash, block->nonce);

        /* Create new hashing context */
        ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, buffer, strlen(buffer));
        EVP_DigestFinal_ex(ctx, hash, &hash_len);
        EVP_MD_CTX_free(ctx);

        bytes_to_hex(hash, output_hash, hash_len);
}

/**
 * check_difficulty - Verify if hash meets difficulty requirement
 * @hash: hash string to check
 * @difficulty: required number of leading zeros
 *
 * Description: Checks if hash begins with required number of zeros
 * Return: 1 if difficulty met, 0 otherwise
 */
int check_difficulty(const char *hash, int difficulty)
{
        int i;

        for (i = 0; i < difficulty; i++)
        {
                if (hash[i] != '0')
                {
                        return (0);
                }
        }
        return (1);
}

/**
 * initialize_blockchain - Create new blockchain
 * @difficulty: initial mining difficulty
 *
 * Description: Allocates and initializes blockchain structure
 * Return: pointer to new blockchain or NULL on failure
 */
Blockchain *initialize_blockchain(int difficulty)
{
        Blockchain *chain;

        chain = (Blockchain *)malloc(sizeof(Blockchain));
        if (chain == NULL)
                return (NULL);

        chain->head = NULL;
        chain->difficulty = difficulty;
        chain->length = 0;
        return (chain);
}

/**
 * create_genesis_block - Create first block of blockchain
 *
 * Description: Initializes genesis block with default values
 * Return: pointer to genesis block or NULL on failure
 */
Block *create_genesis_block(void)
{
        Block *genesis;

        genesis = (Block *)malloc(sizeof(Block));
        if (genesis == NULL)
                return (NULL);

        genesis->index = 0;
        genesis->timestamp = time(NULL);
        genesis->transaction_count = 1;
        strcpy(genesis->transactions[0].data, "Genesis Block");
        genesis->transactions[0].timestamp = genesis->timestamp;
        strcpy(genesis->previous_hash, "0000000000000000000000000000000000000000000000000000000000000000");
        genesis->nonce = 0;
        genesis->next = NULL;

        calculate_block_hash(genesis, genesis->hash);
        return (genesis);
}

/**
 * mine_block - Perform proof-of-work to mine new block
 * @chain: pointer to blockchain
 * @transactions: array of transactions to include
 * @transaction_count: number of transactions
 *
 * Description: Creates new block and performs mining operation
 * Return: pointer to mined block or NULL on failure
 */
Block *mine_block(Blockchain *chain, Transaction *transactions, int transaction_count)
{
        clock_t start, end;
        Block *new_block;
        double mining_time;
        int i;

        start = clock();

        new_block = (Block *)malloc(sizeof(Block));
        if (new_block == NULL)
                return (NULL);

        new_block->index = chain->length;
        new_block->timestamp = time(NULL);
        new_block->transaction_count = transaction_count;

        /* Copy transactions */
        for (i = 0; i < transaction_count; i++)
        {
                new_block->transactions[i] = transactions[i];
        }

        /* Set previous hash */
        if (chain->head != NULL)
        {
                strcpy(new_block->previous_hash, chain->head->hash);
        }
        else
        {
                strcpy(new_block->previous_hash,
                       "0000000000000000000000000000000000000000000000000000000000000000");
        }

        /* Proof of Work */
        new_block->nonce = 0;
        do
        {
                calculate_block_hash(new_block, new_block->hash);
                new_block->nonce++;
        } while (!check_difficulty(new_block->hash, chain->difficulty));

        new_block->next = NULL;

        end = clock();
        mining_time = ((double)(end - start)) / CLOCKS_PER_SEC;

        printf("\nBlock mined!\n");
        printf("Index: %d\n", new_block->index);
        printf("Hash: %s\n", new_block->hash);
        printf("Nonce: %lu\n", new_block->nonce);
        printf("Mining time: %.3f seconds\n", mining_time);

        return (new_block);
}

/**
 * add_block - Add block to blockchain
 * @chain: pointer to blockchain
 * @block: pointer to block to add
 *
 * Description: Adds new block to beginning of chain
 * Return: void
 */
void add_block(Blockchain *chain, Block *block)
{
        if (!chain || !block)
                return;

        if (chain->head == NULL)
        {
                chain->head = block;
        }
        else
        {
                block->next = chain->head;
                chain->head = block;
        }
        chain->length++;
}

/**
 * verify_blockchain - Verify integrity of blockchain
 * @chain: pointer to blockchain
 *
 * Description: Checks hash links and recalculates hashes to verify integrity
 * Return: 1 if valid, 0 if invalid
 */
int verify_blockchain(Blockchain *chain)
{
        Block *current;
        Block *next;
        char calculated_hash[HASH_SIZE];

        if (!chain || !chain->head)
                return (0);

        current = chain->head;
        next = current->next;

        while (next != NULL)
        {
                calculate_block_hash(current, calculated_hash);
                if (strcmp(calculated_hash, current->hash) != 0)
                {
                        return (0);
                }

                if (strcmp(next->hash, current->previous_hash) != 0)
                {
                        return (0);
                }

                current = next;
                next = next->next;
        }

        return (1);
}

/**
 * print_blockchain - Display all blocks in blockchain
 * @chain: pointer to blockchain
 *
 * Description: Prints details of all blocks in chain
 * Return: void
 */
void print_blockchain(Blockchain *chain)
{
        Block *current;
        int i;

        if (!chain)
                return;

        current = chain->head;
        printf("\n=== Blockchain ===\n");
        while (current != NULL)
        {
                printf("\nBlock %d\n", current->index);
                printf("Timestamp: %ld\n", current->timestamp);
                printf("Transactions:\n");
                for (i = 0; i < current->transaction_count; i++)
                {
                        printf("  %s\n", current->transactions[i].data);
                }
                printf("Hash: %s\n", current->hash);
                printf("Previous Hash: %s\n", current->previous_hash);
                printf("Nonce: %lu\n", current->nonce);
                printf("---------------\n");
                current = current->next;
        }
}

/**
 * main - Entry point
 *
 * Description: Tests blockchain implementation with different difficulties
 * Return: 0 on success
 */
int main(void)
{
        int difficulty;
        Blockchain *chain;
        Block *genesis;
        Block *new_block;
        Transaction transactions[3];
        Block *current;
        Block *temp;

        /* Test different difficulty levels */
        for (difficulty = 1; difficulty <= MAX_DIFFICULTY; difficulty++)
        {
                printf("\n=== Testing difficulty %d ===\n", difficulty);

                /* Initialize blockchain */
                chain = initialize_blockchain(difficulty);
                if (!chain)
                        return (1);

                /* Create and add genesis block */
                genesis = create_genesis_block();
                if (!genesis)
                {
                        free(chain);
                        return (1);
                }
                add_block(chain, genesis);

                /* Create sample transactions */
                strcpy(transactions[0].data, "Alice sends 10 BTC to Bob");
                transactions[0].timestamp = time(NULL);
                strcpy(transactions[1].data, "Bob sends 5 BTC to Charlie");
                transactions[1].timestamp = time(NULL);
                strcpy(transactions[2].data, "Charlie sends 3 BTC to David");
                transactions[2].timestamp = time(NULL);

                /* Mine and add new block */
                new_block = mine_block(chain, transactions, 3);
                if (!new_block)
                {
                        /* Clean up chain */
                        current = chain->head;
                        while (current != NULL)
                        {
                                temp = current;
                                current = current->next;
                                free(temp);
                        }
                        free(chain);
                        return (1);
                }
                add_block(chain, new_block);

                /* Verify and print blockchain */
                printf("\nBlockchain verification: %s\n",
                       verify_blockchain(chain) ? "VALID" : "INVALID");
                print_blockchain(chain);

                /* Clean up */
                current = chain->head;
                while (current != NULL)
                {
                        temp = current;
                        current = current->next;
                        free(temp);
                }
                free(chain);
        }

        return (0);
}