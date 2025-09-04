
#include "../include/WhitelistManager.hpp"
#include "../include/Logger.hpp" // For logging
#include <fstream>
#include <sstream>

//Singleton pattern
WhitelistManager& WhitelistManager::instance() {
    static WhitelistManager instance;
    return instance;
}

WhitelistManager::WhitelistManager() {
    Logger::instance().log(LogLevel::INFO, "WhitelistManager initialized.");
}

WhitelistManager::~WhitelistManager() {
    Logger::instance().log(LogLevel::INFO, "WhitelistManager shut down.");
}

bool WhitelistManager::loadWhiteList(const std::string& filename) {

    std::lock_guard<std::mutex> lock(whiteListmutex);

    std::ifstream file(filename);

    if (!file.is_open()) {

        Logger::instance().log(LogLevel::ERROR, "Failed to open whitelist file: " + filename);
        return false;
    }

    whitelistedHashes.clear();
    std::string line;
    int hashCount = 0;

    while (std::getline(file, line)) {
        //clear the blanks
        std::stringstream ss(line);
        std::string hash;
        ss >> hash;

        if (hash.length() == 64) { //SHA-256 hash size = 64
            whitelistedHashes.insert(hash);
            hashCount++;
        }

    }


    Logger::instance().log(
        LogLevel::INFO,
        "Loaded " + std::to_string(hashCount) + " hashes into whitelist from " + filename
    );

    return true;


}

bool WhitelistManager::isWhiteListed(const std::string& hash) const {

    std::lock_guard<std::mutex> lock(whiteListmutex);

    return whitelistedHashes.find(hash) != whitelistedHashes.end();

}