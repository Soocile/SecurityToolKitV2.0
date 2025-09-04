

#include "../include/RiskAnalyzer.hpp"
#include "../include/SignatureEngine.hpp"
#include "../include/HeuristicEngine.hpp"
#include "../include/WhitelistManager.hpp"
#include "../include/Logger.hpp"
#include <fstream>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

#undef ERROR //clearing the windows's ERROR Macro for using loglevels

#pragma comment(lib,"Advapi32.lib")


 std::string RiskAnalyzer::calculateSHA256(const std::vector<uint8_t>& data) {

     HCRYPTPROV hProv = 0;
     HCRYPTPROV hHash = 0;
     DWORD cbHashSize = 32; // 32 bytes for SHA256
     DWORD dwHashLen = sizeof(DWORD);
     std::string hashStr;

     if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {

         Logger::instance().log(LogLevel::ERROR, "CryptAcquireContext failed.");
         return "";
     }

     //create a hash object
     if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
         CryptReleaseContext(hProv, 0);
         Logger::instance().log(LogLevel::ERROR, "CryptCreateHash failed.");
         return "";
     }

     // Add the file data to HASH
     if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
         CryptDestroyHash(hHash);
         CryptReleaseContext(hProv, 0);
         Logger::instance().log(LogLevel::ERROR, "CryptHashData failed.");
         return "";
     }

     //get the hash value
     std::vector<BYTE> hash(cbHashSize);
     if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &cbHashSize, 0)) {
         CryptDestroyHash(hHash);
         CryptReleaseContext(hProv, 0);
         Logger::instance().log(LogLevel::ERROR, "CryptGetHashParam failed.");
         return "";
     }

     //free the hash object and provider

     CryptDestroyHash(hHash);
     CryptReleaseContext(hProv, 0);

     //transform the HASH to hex 
     std::stringstream ss;

     for (BYTE byte : hash) {
         ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
     }

     return ss.str();

}

 std::vector<uint8_t> RiskAnalyzer::readFileToBytes(const std::string& filePath) {

     std::ifstream file(filePath, std::ios::binary | std::ios::ate);

     if (!file.is_open()) {
         throw std::runtime_error("Failed to open file: " + filePath);
     }


     std::streamsize fileSize = file.tellg();
     file.seekg(0, std::ios::beg);

     std::vector<uint8_t> data(static_cast<size_t>(fileSize));
     if (!file.read(reinterpret_cast<char*>(data.data()), fileSize)) {
         throw std::runtime_error("Failed to read file: " + filePath);
     }

     return data;
 }

 bool RiskAnalyzer::initialize(const std::string& signatureFile, const std::string& whitelist_file) {
     Logger::instance().log(LogLevel::INFO, "Initializing analysis engines...");

     //start the signature engine

     if (!SignatureEngine::loadSignatures(signatureFile)) {
         Logger::instance().log(LogLevel::ERROR, "Failed to load signatures.");
         return false;
     }

     // Start the WhiteList Manager.
     if (!WhitelistManager::instance().loadWhiteList(whitelist_file)) {
         Logger::instance().log(LogLevel::ERROR, "Failed to load whitelist.");
         return false;
     }

     Logger::instance().log(LogLevel::INFO, "All engines initialized successfully.");
     return true;

 }

 AnalysisResult RiskAnalyzer::analyzeFile(const std::string& filePath) {

     AnalysisResult result;
     result.filePath = filePath;

     //read file to memory
     std::vector<uint8_t> fileData;

     try {
         fileData = readFileToBytes(filePath);

     }
     catch (const std::exception& e) {
         Logger::instance().log(LogLevel::ERROR, "File read error: " + std::string(e.what()));
         return result;
     }

     //1. White List Control (High priority)
     try {
         std::string fileHash = calculateSHA256(fileData);

         if (WhitelistManager::instance().isWhiteListed(fileHash)) {
             result.isMalicious = false;
             result.detectedBy = "Whitelist";
             Logger::instance().log(LogLevel::INFO, "File is whitelisted. Scan complete.");
             return result;
         }
     }
     catch (const std::exception& e) {
         Logger::instance().log(LogLevel::ERROR, "SHA256 calculation error: " + std::string(e.what()));
         //Continue scanning if an error occurs.
     }


     //2. Signature Scan

     std::string detectedThreat;
     if (SignatureEngine::scanFile(fileData, filePath, detectedThreat)) {
         result.isMalicious = true;
         result.detectedBy = "Signature";
         result.threatName = detectedThreat;
         Logger::instance().log(
             LogLevel::CRITICAL,
             "Signature match found! Threat: " + result.threatName
         );
         QuarantineManager::instance().quarantineFile(filePath, detectedThreat);
         return result;
     }

     //3. Heuristic Analysis


     HeuristicResult heuristicResult = HeuristicEngine::analyze(fileData);
     if (heuristicResult.isSuspicious) {
         result.isMalicious = true;
         result.detectedBy = "Heuristic";
         result.threatName = heuristicResult.details;
         result.heuristicScore = heuristicResult.score;
         Logger::instance().log(
             LogLevel::WARNING,
             "Heuristic analysis flagged file. Score: " + std::to_string(result.heuristicScore)
         );
         Logger::instance().log(LogLevel::WARNING, "Details: " + heuristicResult.details);

         QuarantineManager::instance().quarantineFile(filePath, "Suspicious_file");
     }

     return result;

 }
