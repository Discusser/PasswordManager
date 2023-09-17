#pragma once

#include <sodium/sodium.h>

#include <string>
#include <vector>

class Entry
{
public:
	char* password;
	std::string email;
	std::string name;
	std::string notes;
	std::string url;
	std::string username;
	unsigned long long encryptedLength;
	unsigned char nonce[crypto_box_NONCEBYTES];
};

std::string hexToText(const std::string& in);
std::string textToHex(const std::string& in);
std::vector<Entry> readEntries(std::string path);
void addEntry(Entry entry, std::string path);