#pragma once

#include "config.h"

#include <string>

class PasswordManager
{
public:
    Config Config;
    unsigned char* key;
};

//bool doesKeyMatchMasterPassword();
bool isMasterPasswordSet();
bool isSaltSet();
int mainLoop();
std::string getHashedMasterPassword();
std::string sha256(std::string str);
unsigned char* decryptPassword(unsigned char* encrypted, unsigned long long encryptedLen, unsigned char* key, unsigned char* nonce);
unsigned char* encryptPassword(std::string password, unsigned char* key, unsigned char* nonce, unsigned long long* encryptedPasswordLen);
unsigned char* generateKey(unsigned char* salt, std::string passwd);
unsigned char* getSalt();
void addEntry();
void askMasterPassword();
void clearConsole();
void createMasterPassword();
void listEntries(bool showPassword);
void printLineSeparator();
void resetMasterPassword();
void setMasterPassword(std::string password);
void setSalt(unsigned char* salt);
void showHelp();