#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <unistd.h> // Для getpass()
#include "logs.h"
#define MAX_USERS 2
#define MAX_USERNAME_LENGTH 20
#define MAX_PASSWORD_LENGTH 20
#define HASH_LENGTH 20 // SHA-1 hash length in bytes

struct User {
    char username[MAX_USERNAME_LENGTH];
    unsigned char passwordHash[HASH_LENGTH];
};

struct User users[MAX_USERS];
int numUsers = 0;

void hashPassword(const char* password, unsigned char* hash) {
    SHA1((unsigned char*)password, strlen(password), hash);
}

void loadUsersFromFile(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("Error: Unable to open file '%s' for reading.\n", filename);
        return;
    }
    
    while (fread(&users[numUsers], sizeof(struct User), 1, file) == 1) {
        numUsers++;
    }
    
    fclose(file);
}

void saveUsersToFile(const char* filename) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        printf("Error: Unable to open file '%s' for writing.\n", filename);
        return;
    }
    
    fwrite(users, sizeof(struct User), numUsers, file);
    
    fclose(file);
}

int findUser(const char* username) {
    for (int i = 0; i < numUsers; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return i; // User found
        }
    }
    return -1; // User not found
}

int addUser(const char* username, const char* password) {
    if (numUsers < MAX_USERS) {
        if (findUser(username) == -1) {
            struct User newUser;
            strcpy(newUser.username, username);
            hashPassword(password, newUser.passwordHash);
            memcpy(&users[numUsers], &newUser, sizeof(struct User));
            numUsers++;
            printf("User '%s' added successfully.\n", username);
            log("user added succesfully");
            return 1; // User added successfully
        } else {
            printf("User '%s' already exists.\n", username);
            log("user already exists");
            return 0; // User already exists
        }
    } else {
        printf("Cannot add more users. User limit reached.\n");
        log("Cannot add more users. User limit reached.");
        return 0; // User limit reached
    }
}

int authenticate(const char* username, const char* password) {
    unsigned char passwordHash[HASH_LENGTH];
    hashPassword(password, passwordHash);

    for (int i = 0; i < numUsers; i++) {
        if (strcmp(users[i].username, username) == 0 && memcmp(users[i].passwordHash, passwordHash, HASH_LENGTH) == 0) {
            return 1; // Authentication successful
        }
    }
    return 0; // Authentication failed
}

int auth()
{
    loadUsersFromFile("users.dat");
    log("starting authenfication");
    char username[MAX_USERNAME_LENGTH];
    char *password;

    printf("Enter username: ");
    scanf("%s", username);
    
    password = getpass("Enter password: ");

    if (authenticate(username, password)) {
        printf("Authentication successful. Welcome, %s!\n", username);
        char st[50]="Authentication successful. Welcome, ";
        strcat(st,username);
        log(st);
    } else {
        printf("Authentication failed. Invalid username or password.\n");
        log("Authentication failed");
        printf("Would you like to create a new account? (yes/no): ");
        char choice[4];
        scanf("%s", choice);
        if (strcmp(choice, "yes") == 0) {
            password = getpass("Enter password for the new account: ");
            addUser(username, password);
            saveUsersToFile("users.dat");
        }
        else 
        {
            log("exit program at authenfication");
            log("session end\n");
        }
        return 0;
    }
    return 1;
}
