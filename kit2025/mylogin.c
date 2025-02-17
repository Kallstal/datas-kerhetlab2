#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <stdbool.h>
#include "pwdblib.h"
#include <sys/types.h>
#include <sys/wait.h>

#define USERNAME_SIZE 32
#define NOUSER -1
#define MAX_FAILED_ATTEMPTS 3
#define TIME_TO_RESET 5

// Har inte skrivit i C innan, därför lägger jag in en massor av kommentarer så att jag fattar vad varje linje gör.

void read_username(char *username){
    printf("login: ");
    fgets(username, USERNAME_SIZE, stdin); // Reads the input username. The username is stored in the memory location pointed to by the username parameter 
    username[strcspn(username, "\n")] = '\0'; // Remove newline
}

bool check_password(const char *password, const char *hashed_password){
    char *computed_hash = crypt(password, hashed_password); //A pointer to a hashed password.
    if (!computed_hash) return false;
    return strcmp(computed_hash, hashed_password) == 0; // Comapres so that the hashed 
    // stored password and the computed one matches. Then it returns 0
}

int authenticate_user(const char *username){
    struct pwdb_passwd *user = pwdb_getpwnam(username); //pwdb_getpwnam(username) searches for a user in the password database. 
    // If the user exists, it returns a pointer to a struct pwdb_passwd containing user details.
    //If not, it returns NULL. The user struct is then used to verify login credentials and track login statistics.
    // In short it Fetch User Data from the Password Database
    char *password = getpass("Password: "); // Char eftersom det är en pointer

    if (user == NULL || !check_password(password, user->pw_passwd)) { //pw_passwd är där den hashade versionen av 
    // användarens lösenord ligger
        return NOUSER;
    }
    return 0; // Password correct
}
//From "pwdblib.h"
/*struct pwdb_passwd {
    char *pw_name;   users login name 
    char *pw_passwd; 2 bytes salt value + encrypted password 
    *int pw_uid;      user id 
    int pw_gid;      group id 
    char *pw_gecos;  real name
    char *pw_dir;    home directory
    char *pw_shell;  preferred shell
    int pw_failed;   number of contiguous unsuccessful logins
    int pw_age;      number of successful logins 
  };*/

int main(){
    char username[USERNAME_SIZE]; //Allocates a fixed-size buffer in memory to store a string (the username)
    struct pwdb_passwd *user; // Creates a pointer to pwdb_passwd

    while (1){ // Forever loop
        read_username(username);
        user = pwdb_getpwnam(username);

        if (user != NULL && user->pw_failed >= MAX_FAILED_ATTEMPTS){
            printf("Account locked due to too many failed login attempts.\n");
            return 1;
        }

        if (authenticate_user(username) == 0 && user != NULL) //Passwprd correct
        {
            printf("Successful login!\n");
            user->pw_failed = 0;
            user->pw_age++;
            pwdb_update_user(user); // updates the user in the password file

            if (user->pw_age >= TIME_TO_RESET){
                printf("5 successful logins, you should reset your password\n");
            }


            printf("uid = %d, gid = %d, euid = %d, egid = %d\n", getuid(), getgid(), geteuid(), getegid());
            pid_t pid = fork(); // forking starts, duplicates the parent process. Process ID (0 for the child)
            if (pid == 0){
                execlp("cmd.exe", "cmd.exe", "/c", "start", "/wait", "wsl", NULL);
            }
            
            // Parent process - fattar inte denna del kod
            int child_status; //child_status stores the exit status of the child process
            waitpid(pid, &child_status, 0); //The value of child_status is determined by the waitpid()
            //waints until the child process in closed
            printf("Terminal closed. Restarting...\n");
            continue;
            // Not sure if I've properly implemented the second part of lab 2
        }

        if (user == NULL){
            printf("Incorrect password or username.\n");
            continue;
        }        

        user->pw_failed++;
        pwdb_update_user(user);

        printf("Incorrect password or username.\n");
    }
    return 1;
}
