# Blockchain-Inspired Todo List

A C implementation of a todo list application that demonstrates blockchain-like features such as immutability, data integrity, and hash chaining.

## Features

- Task management (add, update, delete, list)
- Cryptographic hashing using SHA-256
- Blockchain-like immutability
- Data integrity verification
- Chain-based task linking
- Tamper detection demonstration

## Prerequisites

Before compiling and running the program, ensure you have the following installed:

### On Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install build-essential
sudo apt-get install libssl-dev
```

### On macOS:

```bash
brew install openssl
```

### On Windows:

Install MinGW and OpenSSL development libraries.

## Compilation

To compile the program:

```bash
# For Linux/macOS
gcc -o todo_app main.c -lssl -lcrypto

# For macOS (if OpenSSL is installed via Homebrew)
gcc -o todo_app main.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto

# For Windows (MinGW)
gcc -o todo_app.exe main.c -I<path_to_openssl_include> -L<path_to_openssl_lib> -lssl -lcrypto
```

## Running the Program

After compilation, run the program:

```bash
./todo_app    # On Linux/macOS
todo_app.exe  # On Windows
```

## Usage

The program provides a menu-driven interface with the following options:

1. Add Task: Create a new task
2. Update Task Status: Change a task's status
3. List Tasks: View all tasks
4. Verify Task Integrity: Check if a task has been tampered with
5. Delete Task: Remove a task
6. Demonstrate Immutability: Show how tampering is detected
7. Exit: Close the program

## Blockchain-like Features Explained

### 1. Hash Chaining

- Each task contains a hash of its own data
- Tasks are linked through 'previous hash' references
- Similar to how blockchain blocks are linked

### 2. Immutability

- Direct modifications to task data are detected
- Changes must go through proper update functions
- Hash verification ensures data integrity

### 3. Integrity Verification

- Each task's current state is hashed and compared with stored hash
- Previous hash links are verified
- Any tampering is immediately detected

### 4. Task Structure

```c
typedef struct {
    int task_id;
    char description[MAX_DESCRIPTION];
    TaskStatus status;
    char hash[HASH_SIZE];
    char prev_hash[HASH_SIZE];
    time_t timestamp;
} Task;
```

### 5. Error Handling

The program includes comprehensive error handling for:

- Task list capacity limits
- Invalid task IDs
- Memory allocation failures
- Hash calculation issues
- Data integrity violations

## Example Usage

1. Adding a task:

```
Choose an option: 1
Enter task description: Complete project report
Task added successfully!
```

2. Verifying integrity:

```
Choose an option: 4
Enter task ID to verify: 0
Task integrity verified!
```

3. Demonstrating tampering detection:

```
Choose an option: 6
Enter task ID to demonstrate tampering: 0
[Shows original state]
[Simulates tampering]
[Shows compromised state]
```
