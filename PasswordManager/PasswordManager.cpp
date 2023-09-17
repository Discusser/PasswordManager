#include "entry.h"
#include "PasswordManager.h"

#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <sodium/sodium.h>

#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <string>

#define PWHASH_OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define PWHASH_MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE
#define PWHASH_ALG crypto_pwhash_ALG_DEFAULT

PasswordManager manager = PasswordManager();

int main()
{
    if (sodium_init() < 0)
    {
        std::cout << "Could not initialize libsodium" << std::endl;
        return 1;
    }

    manager.Config = Config::GetConfig();

    if (!isSaltSet())
    {
        unsigned char salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof(salt));
        setSalt(salt);
        std::cout << "created new salt " << std::endl;
    }

    manager.key = generateKey(getSalt(), getHashedMasterPassword());

    std::cout << "Password manager b0.1" << std::endl;
    printLineSeparator();

    if (!isMasterPasswordSet())
    {
        std::cout << "You have no master password set!" << std::endl;
        createMasterPassword();
    }
    else
    {        
        askMasterPassword();
    }

    std::cout << std::endl << "Welcome!" << std::endl;
    showHelp();

    return mainLoop();
}

bool isMasterPasswordSet()
{
    return getHashedMasterPassword() != "";
}

bool isSaltSet()
{
    return (char*)getSalt() != "";
}

int mainLoop()
{
    while (true)
    {
        std::string input;
        std::cout << ">> ";
        std::getline(std::cin, input);

        if (input == "l")
            listEntries(false);
        else if (input == "lsp")
            listEntries(true);
        else if (input == "r")
            resetMasterPassword();
        else if (input == "a")
            addEntry();
        else if (input == "q")
            return 0;
        else if (input == "h")
            showHelp();
        else if (input == "clr")
            clearConsole();
        else if (input == "")
            continue;
        else
            showHelp();
    }

    return 0;
}

std::string getHashedMasterPassword()
{
    std::ifstream file;

    if (manager.Config.MasterPasswordLocation == "")
        return "";

    file.open(manager.Config.MasterPasswordLocation, std::ios::in);

    std::string hash;
    std::getline(file, hash);

    file.close();

    return hash;
}

std::string sha256(std::string str)
{
    std::string digest;

    CryptoPP::SHA256 hash;
    CryptoPP::StringSource source(str, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));

    for (unsigned int i = 0, s = static_cast<unsigned int>(digest.size()); i < s; i++)
        digest[i] = static_cast<char>(tolower(digest[i]));

    return digest;
}

unsigned char* decryptPassword(unsigned char* encrypted, unsigned long long encryptedLen, unsigned char* key, unsigned char* nonce)
{
    // Use calloc and add 1 byte to create a NULL terminated string
    unsigned char* decryptedPassword = (unsigned char*)calloc(1, encryptedLen - crypto_secretbox_MACBYTES + 1);
    
    if (crypto_secretbox_open_easy(decryptedPassword, encrypted, encryptedLen, nonce, key) != 0)
    {
        std::cout << "An error occured while decrypting a password";
    }

    return decryptedPassword;
}

unsigned char* encryptPassword(std::string password, unsigned char* key, unsigned char* nonce, unsigned long long* encryptedPasswordLen)
{
    unsigned long long passwordLen = password.size();
    const unsigned char* uPassword = (const unsigned char*)password.c_str();
    unsigned long long encryptedLen = crypto_secretbox_MACBYTES + passwordLen;
    unsigned char* encryptedPassword = (unsigned char*)malloc(encryptedLen);
    unsigned char generatedNonce[crypto_secretbox_NONCEBYTES];
    *encryptedPasswordLen = encryptedLen;

    randombytes_buf(generatedNonce, sizeof(generatedNonce));
    memcpy(nonce, generatedNonce, sizeof(generatedNonce));

    crypto_secretbox_easy(encryptedPassword, uPassword, passwordLen, generatedNonce, key);

    return encryptedPassword;
}

unsigned char* generateKey(unsigned char* salt, std::string passwd)
{
    unsigned long long keyLen = crypto_box_SEEDBYTES;
    unsigned char* key = (unsigned char*)malloc(keyLen);

    if (crypto_pwhash(key, keyLen, passwd.c_str(), passwd.size(), salt, PWHASH_OPSLIMIT, PWHASH_MEMLIMIT, PWHASH_ALG) != 0)
    {
        std::cout << "An error occured during key generation" << std::endl;
    }

    return key;
}

unsigned char* getSalt()
{
    std::ifstream file;

    file.open(manager.Config.SaltLocation, std::ios::binary);

    unsigned char* salt = (unsigned char*)calloc(1, crypto_pwhash_SALTBYTES);
    file.read((char*)salt, crypto_pwhash_SALTBYTES);

    file.close();

    return salt;
}

void addEntry()
{
    Entry entry{};

    while (true)
    {
        std::cout << "Entry name:   ";
        std::getline(std::cin, entry.name);

        if (entry.name != "")
            break;
    }

    std::string password;

    std::cout << "URL:          ";
    std::getline(std::cin, entry.url);
    std::cout << "Username:     ";
    std::getline(std::cin, entry.username);
    std::cout << "Email:        ";
    std::getline(std::cin, entry.email);
    std::cout << "Password:     ";
    std::getline(std::cin, password);

    unsigned long long encryptedLen = 0;
    unsigned char* key = manager.key;
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char* encryptedPassword = encryptPassword(password, key, nonce, &encryptedLen);

    entry.encryptedLength = encryptedLen;
    memcpy(entry.nonce, nonce, sizeof(nonce));
    entry.password = (char*)calloc(1, encryptedLen);
    memcpy(entry.password, (char*)encryptedPassword, encryptedLen);
    password = "";

    std::cout << "Notes:        ";
    std::getline(std::cin, entry.notes);

    addEntry(entry, manager.Config.EntriesLocation);
}

void askMasterPassword()
{
    std::ifstream file;
    std::string hash;
    file.open(manager.Config.MasterPasswordLocation, std::ios::in);
    std::getline(file, hash);
    file.close();

    std::string masterPassword;
    while (true)
    {
        std::cout << "Enter your master password: ";
        std::getline(std::cin, masterPassword);
        if (sha256(masterPassword) != hash)
            std::cout << "Wrong password, try again" << std::endl;
        else
        {
            masterPassword = "";
            break;
        }
    }
}

void clearConsole()
{
    std::cout << "\x1B[2J\x1B[H";
}

void createMasterPassword()
{
    std::string password;
    std::string confirmationPassword;
    std::string hash;
    std::string oldPassword = getHashedMasterPassword();

    while (true)
    {
        std::cout << "Create a master password: ";
        std::getline(std::cin, password);
        std::cout << "Confirm password:         ";
        std::getline(std::cin, confirmationPassword);

        if (password != confirmationPassword)
            std::cout << std::endl << "Passwords don't match, try again" << std::endl;
        else
        {
            hash = sha256(password);
            password = "";
            confirmationPassword = "";
            break;
        }
    }

    std::string backupFile = manager.Config.EntriesLocation + ".bak";

    if (std::filesystem::exists(backupFile))
        remove(backupFile.c_str());

    if (rename(manager.Config.EntriesLocation.c_str(), backupFile.c_str()))
    {
        std::cout << "There was an error when backing up entries. New master password will not be set";
        return;
    }

    std::ofstream file;
    file.open(manager.Config.EntriesLocation, std::ios::app);

    unsigned char* oldKey = manager.key;
    unsigned char* newKey = generateKey(getSalt(), hash);

    std::vector<Entry> entries = readEntries(backupFile);
    for (unsigned int i = 0; i < entries.size(); i++)
    {
        std::string decrypted;
        if (entries[i].encryptedLength != 0 || strcmp((char*)entries[i].nonce, "") != 0)
            decrypted = std::string((char*)decryptPassword((unsigned char*)entries[i].password, entries[i].encryptedLength, oldKey, entries[i].nonce));
        else
            decrypted = entries[i].password;
        
        entries[i].password = (char*)encryptPassword(decrypted, newKey, entries[i].nonce, &entries[i].encryptedLength);
        decrypted = "";

        addEntry(entries[i], manager.Config.EntriesLocation);
    }

    setMasterPassword(hash);
    manager.key = newKey;

    std::cout << "Successfully set master password!" << std::endl;
}

void listEntries(bool showPassword)
{
    if (showPassword)
        askMasterPassword();

    std::vector<Entry> entries = readEntries(manager.Config.EntriesLocation);
    for (unsigned int i = 0; i < entries.size(); i++)
    {
        std::cout << "[" << entries[i].name << "]" << std::endl;
        std::cout << "Username: " << entries[i].username << std::endl;
        std::cout << "URL:      " << entries[i].url << std::endl;
        std::cout << "Email:    " << entries[i].email << std::endl;
        std::cout << "Password: ";
        if (showPassword)
        {
            if (entries[i].encryptedLength != 0 || strcmp((char*)entries[i].nonce, "") != 0)
                std::cout << decryptPassword((unsigned char*)entries[i].password, entries[i].encryptedLength, manager.key, entries[i].nonce);
            else
                std::cout << entries[i].password;
        }
        else
            std::cout << std::string(8, '*');
        std::cout << std::endl;
        std::cout << "Notes:    " << entries[i].notes << std::endl;
        std::cout << std::endl;
    }
}

void printLineSeparator()
{
    std::cout << std::endl << "---------------------" << std::endl << std::endl;
}

void resetMasterPassword()
{
    askMasterPassword();
    createMasterPassword();
}

void setMasterPassword(std::string password)
{
    std::ofstream file;

    file.open(manager.Config.MasterPasswordLocation, std::ios::out);
    
    file << password;
    
    file.close();
}

void setSalt(unsigned char* salt)
{
    std::ofstream file;

    file.open(manager.Config.SaltLocation, std::ios::out | std::ios::binary);

    file.write((char*)salt, crypto_pwhash_SALTBYTES);

    file.close();
}

void showHelp()
{
    std::cout << "[l] List entries            [a] Add entry               [r] Reset master password" << std::endl;
    std::cout << "[h] Show this message       [q] Quit      " << std::endl;
    std::cout << "[clr] Clear the console     [lsp] List entries (show passwords)" << std::endl;
}
