
#include"Antivirus.hpp"
#include<iostream>
#include<string>

int main(int argc, char* argv[]) {

	Logger::instance().setLogFile("scan.log");

	std::cout << "Security Toolkit V2.0.0" << std::endl;
	std::cout << "--------------------------" << std::endl;
	Logger::instance().log(LogLevel::INFO, "Application started.");

	std::string signatureFile = "C:\\projects\\SecurityToolKitV2.0\\SecurityToolKitV2.0\\signatures\\malware_signatures.txt"; 
	std::string whitelistFile = "C:\\projects\\SecurityToolKitV2.0\\SecurityToolKitV2.0\\WhiteList\\WhiteList.txt"; 


	if (!RiskAnalyzer::initialize(signatureFile, whitelistFile)) {
		std::cerr << "Engine initialization failed. Exiting." << std::endl;
		Logger::instance().log(LogLevel::ERROR, "Engine initialization failed.");
		return 1;
	}

	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <file_path>" << std::endl;
		Logger::instance().log(LogLevel::WARNING, "No file path provided.");
		return 1;
	}

	std::string filePath = argv[1];
	std::cout << "Scanning file: " << filePath << std::endl;
	Logger::instance().log(LogLevel::INFO, "Scanning started for: " + filePath);

	AnalysisResult result = RiskAnalyzer::analyzeFile(filePath);


	std::cout << "\n--- Scan Result ---" << std::endl;
	if (result.isMalicious) {
		std::cout << "Status: MALICIOUS" << std::endl;
		std::cout << "Detected By: " << result.detectedBy << std::endl;
		std::cout << "Threat Name: " << result.threatName << std::endl;
		if (result.heuristicScore > 0) {
			std::cout << "Heuristic Score: " << result.heuristicScore << std::endl;
		}
		Logger::instance().log(LogLevel::CRITICAL, "Scan finished. MALICIOUS file detected: " + filePath);
	}
	else {
		std::cout << "Status: CLEAN" << std::endl;
		std::cout << "Reason: " << result.detectedBy << std::endl;
		Logger::instance().log(LogLevel::INFO, "Scan finished. File is CLEAN: " + filePath);
	}

	return 0;


}