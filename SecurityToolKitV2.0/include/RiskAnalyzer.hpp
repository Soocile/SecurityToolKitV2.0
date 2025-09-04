
#ifndef SECURITYTOOLKIT_RISKANALYZER_HPP
#define SECURITYTOOLKIT_RISKANALYZER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include"WhiteListManager.hpp"
#include"QuarantineManager.hpp"

//this structure will hold the analyze result
struct AnalysisResult {

    bool isMalicious = false;
    std::string filePath;
    std::string detectedBy = "N/A"; // detected by (which module?)
    std::string threatName = "N/A"; // Name of the threat
    double heuristicScore = 0.0;

};

class RiskAnalyzer {

public:

    static bool initialize(const std::string& signatureFile, const std::string& whitelist_file);

    static AnalysisResult analyzeFile(const std::string& filePath);

private:


    //Reads the file contents into memory.
    static std::vector<uint8_t> readFileToBytes(const std::string& filePath);


    //calculates the SHA-256 of the file
    static std::string calculateSHA256(const std::vector<uint8_t>& data);

};






#endif //SECURITYTOOLKIT_RISKANALYZER_HPP