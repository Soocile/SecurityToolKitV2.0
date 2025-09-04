

#ifndef SECURITYTOOLKIT_FILEWATCHER_HPP
#define SECURITYTOOLKIT_FILEWATCHER_HPP

#include <string>
#include <vector>
#include <filesystem>
#include <unordered_set>
#include"Logger.hpp"
#include"RiskAnalyzer.hpp"



class FileWatcher {
public:

	FileWatcher(const std::string& directory);

	std::vector<std::string> getNewFiles();
	void onFileCreated(const std::string& path);
	static std::vector<uint8_t> readFile(const std::string& path);


private:
	std::string watchDir;
	std::unordered_set<std::string> knownFiles;
};




#endif //SECURITYTOOLKIT_FILEWATCHER_HPP