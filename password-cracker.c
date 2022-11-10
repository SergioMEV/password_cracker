#define _GNU_SOURCE
#include <openssl/md5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERNAME_LENGTH 64
#define PASSWORD_LENGTH 6

// The header for pthread_create and pthread_join
#include <pthread.h>
// The number of threads
#define NUM_THREADS 4
// The first candidate password
#define START_STR "aaaaaa"

/**
 * Find a six character lower-case alphabetic password that hashes
 * to the given hash value. Complete this function for part A of the lab.
 *
 * \param input_hash  An array of MD5_DIGEST_LENGTH bytes that holds the hash of a password
 * \param output      A pointer to memory with space for a six character password + '\0'
 * \returns           0 if the password was cracked. -1 otherwise.
 */
int crack_single_password(uint8_t* input_hash, char* output) {
  // The first candidate password
  char str[] = START_STR;

  // Traverse all the candidate passwords
  while (str[PASSWORD_LENGTH - 1] <= 'z') {
    // An array to store the md5 hash of the candidate password
    uint8_t candidate_hash[MD5_DIGEST_LENGTH];

    // Calculate the md5 hash of the candidate password
    MD5((unsigned char*)str, strlen(str), candidate_hash);

    // Check whether the md5 hash for the candidate password is matched with the input
    if (memcmp(input_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0) {
      // If they are matched, copy the candidate password to the ouput and then end the function
      strncpy(output, str, PASSWORD_LENGTH + 1);
      return 0;
    }
    // Otherwise, move on

    // Move to the next candidate password by incrementing the first character
    str[0]++;

    // Traverse the characters in the candidate password except for the last one
    for (int i = 0; i < PASSWORD_LENGTH - 1; i++) {
      if (str[i] > 'z') {
        // If the character exceeds 'z', change it to 'a', increment the next charcter, and continue the loop
        str[i + 1]++;
        str[i] = 'a';
        continue;
      } else {
        // Otherwise, break the loop
        break;
      }
    }
  }

  // End the function
  return 0;
}

// The size of the hash table
#define TABLE_SIZE 512
// The data type for the hash for the hash table
typedef uint64_t hash_type;

// The struct for the node of the password set
// A linked list is used to resolve hash collisions
typedef struct password_set_node {
  // This field stores the username
  char username[MAX_USERNAME_LENGTH];
  // This field stores the md5 hash
  uint8_t md5_hash[MD5_DIGEST_LENGTH];
  // This field stores the next node
  struct password_set_node* next;
} password_set_node_t;

// The struct for the password set
typedef struct password_set {
  // This field stores the hash table
  password_set_node_t* hash_table[TABLE_SIZE];
  // This field stores the count of the cracked passwords for each thread
  size_t count[NUM_THREADS];
  // This field stores the total number of inputs
  size_t total;
} password_set_t;

// The struct for the thread argument
typedef struct thread_arg {
  // This field stores the pointer of the password set
  password_set_t* passwords;
  //  This field stores the thread id, which would be between 0 and NUM_THREADS
  uint8_t id;
} thread_arg_t;

/**
 * Find a hash for the given key, which is an md5 hash.
 * The hash for the hash table is calculated as follows:
 * 1. Divide the given key, which is the md5 hash, into two parts. Since the size of the md5 hash is 16 bytes, the size of each part is 8 bytes.
 * 2. Convert each of the two parts into a single value by typecasting to hash_type. Since hash_type is uint64_t, the value can hold 8 bytes.
 * 3. Combine the two values into one value with the XOR operator
 * 4. Divide the result by TABLE_SIZE and use the remainder as a hash.
 *
 * \param key  A key that is an md5 hash used to calculate the hash for the hash table
 *
 * \returns A hash for the hash table
 */
hash_type hash_function(uint8_t* key) {
  // Calculate the hash for the hash table as described above and return it
  return (*(hash_type*)key ^ *(hash_type*)(key + 8)) & (TABLE_SIZE - 1);
}

/**
 * Initialize a password set.
 *
 * \param passwords  A pointer to allocated memory that will hold a password set
 */
void init_password_set(password_set_t* passwords) {
  // Set all the elements in the hash table to NULL
  for (size_t i = 0; i < TABLE_SIZE; i++) {
    passwords->hash_table[i] = NULL;
  }

  // Set all the counts for threads to 0
  for (size_t i = 0; i < NUM_THREADS; i++) {
    passwords->count[i] = 0;
  }

  // Set the total number of inputs to 0
  passwords->total = 0;
}

/**
 * Add a password to a password set
 *
 * \param passwords   A pointer to a password set initialized with the function above.
 * \param username    The name of the user being added.
 * \param password_hash   An array of MD5_DIGEST_LENGTH bytes that holds the hash of this user's
 *                        password.
 */
void add_password(password_set_t* passwords, char* username, uint8_t* password_hash) {
  // Create a new password set node
  password_set_node_t* new_node = malloc(sizeof(password_set_node_t));
  // Store the given username
  memcpy(new_node->username, username, MAX_USERNAME_LENGTH);
  // Store the given md5 hash
  memcpy(new_node->md5_hash, password_hash, MD5_DIGEST_LENGTH);

  // Find the hash for the given md5 hash
  hash_type hash = hash_function(password_hash);

  // Add the new node to the hash table using the hash
  new_node->next = passwords->hash_table[hash];
  passwords->hash_table[hash] = new_node;

  // Increment the total number of inputs
  passwords->total++;
}

/**
 * Crack the input passwords by traversing the possible candidate passwords in each thread.
 * Each thread starts with the different first candidate based on its id and checks every fourth character.
 *
 * \param arg  A pointer to thread argument
 *
 * \returns NULL
 */
void* thread_fn(void* arg) {
  // Typecase void* to thread_arg_t* to access the fields in the thread argument
  thread_arg_t* args = (thread_arg_t*)arg;

  // The first candidate password that is different depending on the thread id
  char str[] = START_STR;
  str[0] += args->id;

  // Traverse every fourth candidate password
  while (str[PASSWORD_LENGTH - 1] <= 'z') {
    // Calculate the total number of cracked passwords
    size_t sum = 0;
    for (size_t i = 0; i < NUM_THREADS; i++) {
      sum += args->passwords->count[i];
    }

    // If all the passwords are cracked, end the function
    if (sum == args->passwords->total) {
      return NULL;
    }

    // An array to store the md5 hash of the candidate password
    uint8_t candidate_hash[MD5_DIGEST_LENGTH];

    // Calculate the md5 hash of the candidate password
    MD5((unsigned char*)str, PASSWORD_LENGTH, candidate_hash);

    // Find the hash for the md5 hash of the candidate password
    hash_type hash = hash_function(candidate_hash);

    // Traverse the linked list corresponding to the hash and check whether the md5 hash of the candidate password is matched with one of the inputs
    password_set_node_t* temp_node = args->passwords->hash_table[hash];
    while (temp_node != NULL) {
      if (memcmp(temp_node->md5_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0) {
        // If they are matched, print out the username and the cracked password and increment the count
        printf("%s %s\n", temp_node->username, str);
        args->passwords->count[args->id]++;
      }

      // Move to the next node in the linked list
      temp_node = temp_node->next;
    }

    // Move to the next candidate password
    str[0] += NUM_THREADS;

    // Traverse the characters in the candidate password except for the last one
    for (int i = 0; i < PASSWORD_LENGTH - 1; i++) {
      if (str[i] > 'z') {
        // If the character exceeds 'z', change it to the appropriate character, increment the next charcter, and continue the loop
        str[i] -= 'z' - 'a' + 1;
        str[i + 1]++;
        continue;
      } else {
        // Otherwise, break the loop
        break;
      }
    }
  }

  // End the function
  return NULL;
}

/**
 * Crack all of the passwords in a set of passwords. 
 *
 * \returns The number of passwords cracked in the list
 */
int crack_password_list(password_set_t* passwords) {
  // Arrays for threads and their arguments
  pthread_t threads[NUM_THREADS];
  thread_arg_t args[NUM_THREADS];

  // Assign the thread arguments with the pointer to the password set and their id
  for (uint8_t i = 0; i < NUM_THREADS; i++) {
    args[i].passwords = passwords;
    args[i].id = i;
  }

  // Create the threads
  for (uint8_t i = 0; i < NUM_THREADS; i++) {
    if (pthread_create(&threads[i], NULL, thread_fn, &args[i])) {
      perror("pthread_create failed");
      exit(EXIT_FAILURE);
    }
  }

  // Join the threads
  for (uint8_t i = 0; i < NUM_THREADS; i++) {
    if (pthread_join(threads[i], NULL)) {
      perror("pthread_join failed");
      exit(EXIT_FAILURE);
    }
  }

  // Traverse all the elements in the hash table and free them
  for (size_t i = 0; i < TABLE_SIZE; i++) {
    // Traverse the linked list, which is an element of the hash table
    password_set_node_t* temp_node = passwords->hash_table[i];
    while (temp_node != NULL) {
      password_set_node_t* next_node = temp_node->next;
      free(temp_node);
      temp_node = next_node;
    }
  }

  // Calculate the total number of the cracked passwords and return it
  size_t sum = 0;
  for (uint8_t i = 0; i < NUM_THREADS; i++) {
    sum += passwords->count[i];
  }
  return sum;
}

/**
 * Convert a string representation of an MD5 hash to a sequence
 * of bytes. The input md5_string must be 32 characters long, and
 * the output buffer bytes must have room for MD5_DIGEST_LENGTH
 * bytes.
 *
 * \param md5_string  The md5 string representation
 * \param bytes       The destination buffer for the converted md5 hash
 * \returns           0 on success, -1 otherwise
 */
int md5_string_to_bytes(const char* md5_string, uint8_t* bytes) {
  // Check for a valid MD5 string
  if (strlen(md5_string) != 2 * MD5_DIGEST_LENGTH) return -1;

  // Start our "cursor" at the start of the string
  const char* pos = md5_string;

  // Loop until we've read enough bytes
  for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
    // Read one byte (two characters)
    int rc = sscanf(pos, "%2hhx", &bytes[i]);
    if (rc != 1) return -1;

    // Move the "cursor" to the next hexadecimal byte
    pos += 2;
  }

  return 0;
}

void print_usage(const char* exec_name) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s single <MD5 hash>\n", exec_name);
  fprintf(stderr, "  %s list <password file name>\n", exec_name);
}

int main(int argc, char** argv) {
  if (argc != 3) {
    print_usage(argv[0]);
    exit(1);
  }

  if (strcmp(argv[1], "single") == 0) {
    // The input MD5 hash is a string in hexadecimal. Convert it to bytes.
    uint8_t input_hash[MD5_DIGEST_LENGTH];
    if (md5_string_to_bytes(argv[2], input_hash)) {
      fprintf(stderr, "Input has value %s is not a valid MD5 hash.\n", argv[2]);
      exit(1);
    }

    // Now call the crack_single_password function
    char result[7];
    if (crack_single_password(input_hash, result)) {
      printf("No matching password found.\n");
    } else {
      printf("%s\n", result);
    }

  } else if (strcmp(argv[1], "list") == 0) {
    // Make and initialize a password set
    password_set_t passwords;
    init_password_set(&passwords);

    // Open the password file
    FILE* password_file = fopen(argv[2], "r");
    if (password_file == NULL) {
      perror("opening password file");
      exit(2);
    }

    int password_count = 0;

    // Read until we hit the end of the file
    while (!feof(password_file)) {
      // Make space to hold the username
      char username[MAX_USERNAME_LENGTH];

      // Make space to hold the MD5 string
      char md5_string[MD5_DIGEST_LENGTH * 2 + 1];

      // Make space to hold the MD5 bytes
      uint8_t password_hash[MD5_DIGEST_LENGTH];

      // Try to read. The space in the format string is required to eat the newline
      if (fscanf(password_file, "%s %s ", username, md5_string) != 2) {
        fprintf(stderr, "Error reading password file: malformed line\n");
        exit(2);
      }

      // Convert the MD5 string to MD5 bytes in our new node
      if (md5_string_to_bytes(md5_string, password_hash) != 0) {
        fprintf(stderr, "Error reading MD5\n");
        exit(2);
      }

      // Add the password to the password set
      add_password(&passwords, username, password_hash);
      password_count++;
    }

    // Now run the password list cracker
    int cracked = crack_password_list(&passwords);

    printf("Cracked %d of %d passwords.\n", cracked, password_count);

  } else {
    print_usage(argv[0]);
    exit(1);
  }

  return 0;
}
