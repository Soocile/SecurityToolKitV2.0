
#include"../include/FileWatcher.hpp"
#include<fstream>

FileWatcher::FileWatcher(const std::string& directory) : watchDir(directory) {
  //constructor func
	//When the object is created, it finds existing files in the directory to be monitored.

	for (const auto& entry : std::filesystem::directory_iterator(watchDir)) {

		if (entry.is_regular_file()) {
			knownFiles.insert(entry.path().string());
		}
	}

}

std::vector<std::string> FileWatcher::getNewFiles() {

	std::vector<std::string> newFiles;

	for (const auto& entry : std::filesystem::directory_iterator(watchDir)) {
		if (entry.is_regular_file()) {

			std::string path = entry.path().string();

			//if the file is not one of the known files that we have saw before...
			if (knownFiles.find(path) == knownFiles.end()) {

				newFiles.push_back(path);
				knownFiles.insert(path);

			}
		}
	}
	return newFiles;
}

std::vector<uint8_t> FileWatcher::readFile(const std::string& path) {

	//std::ios::binary ,allows the file to be read byte by byte.
	std::ifstream file(path, std::ios::binary | std::ios::ate);

	//error control
	if (!file.is_open()) {

		//return a free vector if the file is not open
		return {};
	}
	//get the file size
	std::streamsize size = file.tellg();

	if (size == 0) {

		//return a free vector if the file is not open
		return {};
	}

	//get the reading position to the start of the file
	file.seekg(0, std::ios::beg);

	//create a vector to store the read bytes
	std::vector<uint8_t> buffer(size);

	if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {

		//if the reading is unsuccesfull then return a free vector
		return {};
	}

	return buffer;
}

void FileWatcher::onFileCreated(const std::string& path) {

	Logger::instance().log(LogLevel::INFO, "New file created/modified: " + path);

	AnalysisResult result = RiskAnalyzer::analyzeFile(path);

	//Log scan results

	if (result.isMalicious) {
		if (result.detectedBy == "Signature") {
			Logger::instance().log(
				LogLevel::CRITICAL,
				"Threat detected by Signature: " + result.threatName + " in " + path
			);
		}
		else if (result.detectedBy == "Heuristic") {
			Logger::instance().log(
				LogLevel::CRITICAL,
				"Threat detected by Heuristic: " + result.threatName +
				" with score " + std::to_string(result.heuristicScore) + " in " + path
			);
		}
		else {
			Logger::instance().log(LogLevel::INFO, "File is clean: " + path);
		}
	}
}

//could be added onfiledeleted, onfilemodified functions at another time
