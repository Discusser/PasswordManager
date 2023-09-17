#include "config.h"
#include "entry.h"

#include <fstream>
#include <sstream>
#include <iomanip>

std::string hexToText(const std::string& in) {
	std::string output;

	if ((in.length() % 2) != 0) {
		throw std::runtime_error("String is not valid length ...");
	}

	size_t cnt = in.length() / 2;

	for (size_t i = 0; cnt > i; ++i) {
		uint32_t s = 0;
		std::stringstream ss;
		ss << std::hex << in.substr(i * 2, 2);
		ss >> s;

		output.push_back(static_cast<unsigned char>(s));
	}

	return output;
}

std::string textToHex(const std::string& in) {
	std::stringstream ss;

	ss << std::hex << std::setfill('0');
	for (size_t i = 0; in.length() > i; ++i) {
		ss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(in[i]));
	}

	return ss.str();
}

std::vector<Entry> readEntries(std::string path)
{
	std::ifstream file;
	std::string line;
	std::vector<Entry> entries;
	Entry current{};

	file.open(path, std::ios::in);

	while (std::getline(file, line))
	{
		if (line.starts_with(';')) // Comments
			continue;
		else if (line == "")
			continue;
		else if (line.starts_with('[')) // Entry name
		{
			if (current.name != "") // If this is not the first entry we're reading, add the previous one
			{
				entries.push_back(current);
				current = Entry{};
			}

			for (unsigned int i = 1; i < line.size(); i++)
			{
				if (line[i] != ']')
					current.name += line[i];
				else
					break;
			}
		}
		else
		{
			if (line.find('=') == std::string::npos)
				continue;

			std::vector<std::string> pair = Config::splitKeyValue(line);
			std::string key = pair[0];
			std::string value = pair[1];

			if (key == "url")
				current.url = value;
			else if (key == "username")
				current.username = value;
			else if (key == "email")
				current.email = value;
			else if (key == "password")
			{
				std::string txt = hexToText(value);
				current.password = (char*)calloc(1, txt.size());
				memcpy(current.password, txt.c_str(), txt.size());
			}
			else if (key == "notes")
				current.notes = value;
			else if (key == "len")
				current.encryptedLength = atoi(value.c_str());
			else if (key == "nonce")
			{
				memcpy(current.nonce, hexToText(value).c_str(), sizeof(current.nonce));
			}
			//{
			//	char c;
			//	bool readEquals = false;
			//	while (true)
			//	{
			//		c = file.get();
			//		if (c == EOF)
			//			break;
			//		
			//		if (readEquals)
			//			break;
			//		if (c == '=')
			//			readEquals = true;
			//	}

			//	char* nonce;
			//	file.read(nonce, sizeof(current.nonce));
			//	std::string text = hexToText(nonce);
			//	memcpy(current.nonce, text.c_str(), text.size());
			//}
		}
	}

	entries.push_back(current);

	file.close();

	return entries;
}

void addEntry(Entry entry, std::string path)
{
	std::ofstream file;

	file.open(path, std::ios::app);

	file << "[" << entry.name + "]" << std::endl;
	file << "url=" << entry.url << std::endl;
	file << "username=" << entry.username << std::endl;
	file << "email=" << entry.email << std::endl;
	file << "password=";
	//file.write(entry.password.c_str(), entry.encryptedLength);
	file << textToHex(std::string(entry.password, entry.encryptedLength));
	file << std::endl;
	file << "nonce=";
	file << textToHex(std::string((char*)entry.nonce, sizeof(entry.nonce)));
	file << std::endl;
	file << "len=" << entry.encryptedLength << std::endl;
	file << "notes=" << entry.notes << std::endl;
	file << std::endl;

	file.close();
}