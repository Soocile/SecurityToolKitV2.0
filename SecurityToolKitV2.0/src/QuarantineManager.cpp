#include"../include/QuarantineManager.hpp"
#include "../include/Logger.hpp"
#define WIN32_LEAND_AND_MEAN
#include <windows.h>
#include <shlobj.h> // SHGetFolderPath için
#include <string>

#undef ERROR

#pragma comment(lib, "shell32.lib")

QuarantineManager& QuarantineManager::instance() {
    static QuarantineManager instance;
    return instance;
}

QuarantineManager::QuarantineManager() {
    char path[MAX_PATH];

    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path) == S_OK) {
        quarantineDir = std::string(path) + "\\SecurityToolkitV2.0\\Quarantine";

        if (CreateDirectoryA(quarantineDir.c_str(), NULL) ||
            GetLastError() == ERROR_ALREADY_EXISTS) {
            // Make the directory hidden
            SetFileAttributesA(quarantineDir.c_str(), FILE_ATTRIBUTE_HIDDEN);
            Logger::instance().log(LogLevel::INFO, "Quarantine directory created/verified: " + quarantineDir);
        }
        else {
            Logger::instance().log(LogLevel::ERROR, "Failed to create quarantine directory.");
        }

    }
    else {
        Logger::instance().log(LogLevel::ERROR, "Failed to get AppData path.");
        quarantineDir = ".\\Quarantine"; //Use local directory as fallback
    }

}
QuarantineManager::~QuarantineManager() {
    Logger::instance().log(LogLevel::INFO, "QuarantineManager shut down.");
}

bool QuarantineManager::quarantineFile(const std::string& filePath, const std::string& threatName) {
    
    std::lock_guard<std::mutex> lock(quarantineMutex);

    std::string filename = filePath.substr(filePath.find_last_of("\\/") + 1);
    std::string quarantinedFilePath = quarantineDir + "\\" + filename + ".isolated";
   
    //move the file
    if (!MoveFileExA(filePath.c_str(), quarantinedFilePath.c_str(), MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH)) {
        Logger::instance().log(LogLevel::ERROR, "Failed to quarantine file: " + filePath);
        return false;
    }

    //save the meta data of the original file
    std::ofstream metadataFile(quarantinedFilePath + ".meta");

    if (metadataFile.is_open()) {

        metadataFile << "Original Path: " << filePath << std::endl;
        metadataFile << "Threat Name: " << threatName << std::endl;
        metadataFile << "Quarantined At: " << __DATE__ << " " << __TIME__ << std::endl;
        metadataFile.close();
    }
    else {
        Logger::instance().log(LogLevel::ERROR, "Failed to create quarantine metadata file.");
    }

    Logger::instance().log(LogLevel::CRITICAL, "File quarantined: " + filePath);
    return true;

}

bool QuarantineManager::restoreFile(const std::string& quarantinePath) {
    std::lock_guard<std::mutex> lock(quarantineMutex);

    //read the original file path of the meta data file

    std::string metadataPath = quarantinePath + ".meta";
    std::ifstream metadataFile(metadataPath);
    std::string originalPath;

    if (metadataFile.is_open()) {
        std::string line;
        std::getline(metadataFile, line);
        originalPath = line.substr(line.find(":") + 2);
    }
    else {
        Logger::instance().log(LogLevel::ERROR, "Failed to find metadata for restoration.");
        return false;
    }

    std::string restoredPath = originalPath;

    if (MoveFileExA(quarantinePath.c_str(), restoredPath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        // Delete the Meta Data File
        DeleteFileA(metadataPath.c_str());
        Logger::instance().log(LogLevel::INFO, "File restored to: " + restoredPath);
        return true;
    }


    Logger::instance().log(LogLevel::ERROR, "Failed to restore file: " + quarantinePath);
    return false;
}

std::vector<std::string> QuarantineManager::listQuarantinedFiles() const {
    
    //Could be Added later...
    return {};
}