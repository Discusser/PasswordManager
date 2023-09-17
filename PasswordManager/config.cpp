#include "config.h"

#include <fstream>
#include <vector>

Config Config::GetConfig()
{
	Config cfg = Config();

	cfg.Path = GetConfigLocation();

	std::ifstream file;
	std::string line;
	std::string key;
	std::string value;

	file.open(cfg.Path, std::ios::in);

	while (std::getline(file, line))
	{
		if (line.starts_with(';')) // Comments
			continue;
		if (line.starts_with('[')) // Sections (unsupported)
			continue;

		if (line.find('=') == std::string::npos) // Skip the line if it doesn't contain an equal sign
			continue;

		std::vector<std::string> pair = splitKeyValue(line);

		key = pair[0];
		value = pair[1];

		if (key == "masterPasswordLocation")
			cfg.MasterPasswordLocation = value;
		else if (key == "entriesLocation")
			cfg.EntriesLocation = value;
		else if (key == "saltLocation")
			cfg.SaltLocation = value;
	}

	file.close();

	return cfg;
}

std::string Config::GetConfigLocation()
{
	return "passwordManager.ini";
}

std::vector<std::string> Config::splitKeyValue(std::string line)
{
	std::vector<std::string> pair(2);
	std::string current = "";
	unsigned int pairIdx = 0;

	for (unsigned int i = 0, s = static_cast<unsigned int>(line.size()); i < s; i++)
	{
		if (line[i] == '=')
		{
			pair[pairIdx] = current;
			current = "";
			pairIdx++;
			i++;
		}

		if (pairIdx >= pair.capacity())
			break;

		current += line[i];
	}

	pair[pair.capacity() - 1] = current;

	return pair;
}
