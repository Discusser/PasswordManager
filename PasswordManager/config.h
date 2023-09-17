#pragma once

#include <string>
#include <vector>

class Config
{
public:	
	static Config GetConfig();
	static std::string GetConfigLocation();
	static std::vector<std::string> splitKeyValue(std::string line);

	std::string Path = "";
	
	std::string EntriesLocation = "";
	std::string SaltLocation = "";
	std::string MasterPasswordLocation = "";

	Config() = default;
};