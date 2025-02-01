/* Question 1*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>

#define MAX_DESCRIPTION 256
#define MAX_TASKS 100
#define HASH_SIZE SHA256_DIGEST_LENGTH * 2 + 1

// Task status enum
typedef enum
{
        PENDING,
        IN_PROGRESS,
        COMPLETED
} TaskStatus;

// Task structure
typedef struct
{
        int task_id;
        char description[MAX_DESCRIPTION];
        TaskStatus status;
        char hash[HASH_SIZE];
        char prev_hash[HASH_SIZE];
        time_t timestamp;
} Task;

// Blockchain-like todo list structure
typedef struct
{
        Task tasks[MAX_TASKS];
        int task_count;
} TodoList;

/* Function to convert bytes to hexadecimal string */
void bytes_to_hex(unsigned char *bytes, char *hex, int size)
{
        for (int i = 0; i < size; i++)
        {
                sprintf(&hex[i * 2], "%02x", bytes[i]);
        }
        hex[size * 2] = '\0';
}

/* Calculate hash for a task */
void calculate_task_hash(Task *task, char *output_hash)
{
        SHA256_CTX sha256;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        char buffer[512];

        // Concatenate task data
        snprintf(buffer, sizeof(buffer), "%d%s%d%s%ld",
                 task->task_id,
                 task->description,
                 task->status,
                 task->prev_hash,
                 task->timestamp);

        SHA256_Init(&sha256);
        SHA256_Update(&sha256, buffer, strlen(buffer));
        SHA256_Final(hash, &sha256);

        bytes_to_hex(hash, output_hash, SHA256_DIGEST_LENGTH);
}

/* Initialize todo list */
void init_todo_list(TodoList *list)
{
        list->task_count = 0;
        memset(list->tasks, 0, sizeof(list->tasks));
}

/* Add a new task */
int add_task(TodoList *list, const char *description)
{
        if (list->task_count >= MAX_TASKS)
        {
                return -1; // List is full
        }

        Task *new_task = &list->tasks[list->task_count];
        new_task->task_id = list->task_count;
        strncpy(new_task->description, description, MAX_DESCRIPTION - 1);
        new_task->status = PENDING;
        new_task->timestamp = time(NULL);

        // Set previous hash
        if (list->task_count > 0)
        {
                strcpy(new_task->prev_hash, list->tasks[list->task_count - 1].hash);
        }
        else
        {
                strcpy(new_task->prev_hash, "0000000000000000000000000000000000000000000000000000000000000000");
        }

        // Calculate new task hash
        calculate_task_hash(new_task, new_task->hash);
        list->task_count++;

        return new_task->task_id;
}

// Update task status
int update_task_status(TodoList *list, int task_id, TaskStatus new_status)
{
        if (task_id < 0 || task_id >= list->task_count)
        {
                return -1; // Invalid task ID
        }

        Task *task = &list->tasks[task_id];
        char old_hash[HASH_SIZE];
        strcpy(old_hash, task->hash);

        task->status = new_status;
        task->timestamp = time(NULL);
        calculate_task_hash(task, task->hash);

        // Maintaining hash chain intergrity
        for (int i = task_id + 1; i < list->task_count; i++)
        {
                strcpy(list->tasks[i].prev_hash, list->tasks[i - 1].hash);
                calculate_task_hash(&list->tasks[i], list->tasks[i].hash);
        }

        return 0;
}

/* Delete Task */
int delete_task(TodoList *list, int task_id)
{
        if (task_id < 0 || task_id >= list->task_count)
        {
                return -1; // Invalid task ID
        }

        // Shift all tasks after the deleted task
        for (int i = task_id; i < list->task_count - 1; i++)
        {
                memcpy(&list->tasks[i], &list->tasks[i + 1], sizeof(Task));
                list->tasks[i].task_id = i; // Update task ID to maintain sequence
        }

        list->task_count--;

        // Recalculate hashes for all tasks after the deletion point to maintain chain integrity
        for (int i = task_id; i < list->task_count; i++)
        {
                if (i == 0)
                {
                        strcpy(list->tasks[i].prev_hash, "0000000000000000000000000000000000000000000000000000000000000000");
                }
                else
                {
                        strcpy(list->tasks[i].prev_hash, list->tasks[i - 1].hash);
                }
                calculate_task_hash(&list->tasks[i], list->tasks[i].hash);
        }

        return 0;
}

/* Verify task integrity */
int verify_task_integrity(TodoList *list, int task_id)
{
        if (task_id < 0 || task_id >= list->task_count)
        {
                return -1; // Invalid task ID
        }

        Task *task = &list->tasks[task_id];
        char calculated_hash[HASH_SIZE];
        calculate_task_hash(task, calculated_hash);

        // Compare current task hash
        if (strcmp(calculated_hash, task->hash) != 0)
        {
                return 0; // Hash mismatch
        }

        // Verify chain integrity
        if (task_id > 0)
        {
                if (strcmp(task->prev_hash, list->tasks[task_id - 1].hash) != 0)
                {
                        return 0; // Prev hash mismatch
                }
        }

        return 1; // Integrity verified
}

/* Display task status as string */
const char *status_to_string(TaskStatus status)
{
        switch (status)
        {
        case PENDING:
                return "Pending";
        case IN_PROGRESS:
                return "In Progress";
        case COMPLETED:
                return "Completed";
        default:
                return "Unknown";
        }
}

/* List all tasks */
void list_tasks(TodoList *list)
{
        printf("\n=== Task List ===\n");
        for (int i = 0; i < list->task_count; i++)
        {
                Task *task = &list->tasks[i];
                printf("Task ID: %d\n", task->task_id);
                printf("Description: %s\n", task->description);
                printf("Status: %s\n", status_to_string(task->status));
                printf("Hash: %s\n", task->hash);
                printf("Previous Hash: %s\n", task->prev_hash);
                printf("Integrity: %s\n", verify_task_integrity(list, i) ? "Valid" : "COMPROMISED");
                printf("---------------\n");
        }
}

/* Demonstrate Immutability */
void simulate_tampering(TodoList *list, int task_id)
{
        if (task_id < 0 || task_id >= list->task_count)
        {
                printf("Error: Invalid task ID.\n");
                return;
        }

        // Store original state for demonstration
        Task original_task = list->tasks[task_id];
        printf("\n=== Demonstrating Immutability ===\n");
        printf("\nOriginal Task State:\n");
        printf("Task ID: %d\n", original_task.task_id);
        printf("Description: %s\n", original_task.description);
        printf("Status: %s\n", status_to_string(original_task.status));
        printf("Hash: %s\n", original_task.hash);
        printf("Integrity Check: %s\n", verify_task_integrity(list, task_id) ? "Valid" : "COMPROMISED");

        // Simulate unauthorized modification by directly changing the description
        printf("\nAttempting to modify task data directly (simulating unauthorized tampering)...\n");
        strcat(list->tasks[task_id].description, " [TAMPERED]");

        printf("\nTask State After Tampering:\n");
        printf("Task ID: %d\n", list->tasks[task_id].task_id);
        printf("Description: %s\n", list->tasks[task_id].description);
        printf("Status: %s\n", status_to_string(list->tasks[task_id].status));
        printf("Hash: %s\n", list->tasks[task_id].hash); // Note: Hash hasn't been recalculated
        printf("Integrity Check: %s\n", verify_task_integrity(list, task_id) ? "Valid" : "COMPROMISED");

        printf("\nDemonstration Notes:\n");
        printf("1. The task description was modified directly in memory\n");
        printf("2. The hash was not recalculated (simulating unauthorized access)\n");
        printf("3. The integrity check fails because the current data doesn't match the stored hash\n");
        printf("4. This demonstrates how the hash system prevents undetected tampering\n");

        // Restore original state
        list->tasks[task_id] = original_task;
        printf("\nTask restored to original state.\n");
}

/* Update print_menu to include the demonstration option */
void print_menu()
{
        printf("\n=== Blockchain Todo List ===\n");
        printf("1. Add Task\n");
        printf("2. Update Task Status\n");
        printf("3. List Tasks\n");
        printf("4. Verify Task Integrity\n");
        printf("5. Delete Task\n");
        printf("6. Demonstrate Immutability\n");
        printf("7. Exit\n");
        printf("Choose an option: ");
}

int main()
{
        TodoList list;
        init_todo_list(&list);
        char description[MAX_DESCRIPTION];
        int task_id, choice, status;

        while (1)
        {
                print_menu();
                scanf("%d", &choice);
                getchar();

                switch (choice)
                {
                case 1:
                        printf("Enter task description: ");
                        fgets(description, MAX_DESCRIPTION, stdin);
                        description[strcspn(description, "\n")] = 0; // Remove newline

                        if (add_task(&list, description) >= 0)
                        {
                                printf("Task added successfully!\n");
                        }
                        else
                        {
                                printf("Error: Could not add task.\n");
                        }
                        break;

                case 2:
                        printf("Enter task ID: ");
                        scanf("%d", &task_id);
                        printf("Enter new status (0=Pending, 1=In Progress, 2=Completed): ");
                        scanf("%d", &status);

                        if (update_task_status(&list, task_id, status) == 0)
                        {
                                printf("Task status updated successfully!\n");
                        }
                        else
                        {
                                printf("Error: Could not update task status.\n");
                        }
                        break;

                case 3:
                        list_tasks(&list);
                        break;

                case 4:
                        printf("Enter task ID to verify: ");
                        scanf("%d", &task_id);

                        int integrity = verify_task_integrity(&list, task_id);
                        if (integrity == 1)
                        {
                                printf("Task integrity verified!\n");
                        }
                        else if (integrity == 0)
                        {
                                printf("WARNING: Task integrity compromised!\n");
                        }
                        else
                        {
                                printf("Error: Invalid task ID.\n");
                        }
                        break;

                case 5:
                        printf("Enter task ID to delete: ");
                        scanf("%d", &task_id);

                        if (delete_task(&list, task_id) == 0)
                        {
                                printf("Task deleted successfully!\n");
                        }
                        else
                        {
                                printf("Error: Could not delete task.\n");
                        }
                        break;

                case 6:
                        printf("Enter task ID to demonstrate tampering: ");
                        scanf("%d", &task_id);
                        simulate_tampering(&list, task_id);
                        break;

                case 7:
                        printf("Goodbye!\n");
                        return 0;

                default:
                        printf("Invalid option. Please try again.\n");
                }
        }

        return 0;
}