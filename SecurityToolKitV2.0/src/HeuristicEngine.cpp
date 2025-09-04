
#include"../include/HeuristicEngine.hpp"
#include"../Logger.hpp"
#include<map>
#include<cmath>

double HeuristicEngine::getEntropy(const std::vector<uint8_t>& data) {


	if (data.empty()) {
		return 0.0;
	}

	std::map<uint8_t, size_t> byteCounts;

	for (uint8_t byte : data) {
		byteCounts[byte]++;
	}


	double entropy = 0.0;
	const double dataSize = static_cast<double>(data.size());

	for (auto const& [byte, count] : byteCounts) {
		double p = static_cast<double>(count) / dataSize; // probability of the byte
		//Applying Shannon Entropy Formula
		entropy -= p * log2(p);
	}

	return entropy;
}



double HeuristicEngine::checkNOPFlood(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return 0.0;
    }

    // NOP benzeri veya anlamsýz komutlarý tanýmlýyoruz.
    // Bu komutlar, zararlý yazýlýmýn koduna boþluk eklemesinde kullanýlýr.
    const std::vector<uint8_t> suspiciousNops = {
        0x90,       // NOP
        0xCC,       // INT 3 (Debugger breakpoint)
        0xEB, 0xFE, // JMP $ (infinite loop)
        0xEB, 0x01, // JMP +1 (pass the next byte)
        0xF4        // HLT (Stop the processor)
    };

    size_t suspiciousCount = 0;

    for (size_t i = 0; i < data.size(); ++i) {
        // 1 Byte NOP control
        if (data[i] == 0x90 || data[i] == 0xCC || data[i] == 0xF4) {
            suspiciousCount++;
            continue;
        }

        // 2 Byte NOP control
        if (i + 1 < data.size()) {
            if ((data[i] == 0xEB && data[i + 1] == 0xFE) ||
                (data[i] == 0xEB && data[i + 1] == 0x01)) {
                suspiciousCount += 2;
                i += 1; // Ýkinci baytý atla
            }
        }
    }

    //calculate the NOP ratio
    double nopRatio = static_cast<double>(suspiciousCount) / data.size();

    return nopRatio;
}

double HeuristicEngine::checkSuspiciousStrings(const std::vector<uint8_t>& data) {
    double score = 0.0;

    const std::map<std::string, double> suspiciousStrings = {
     {"CreateRemoteThread", 10.0},
     {"VirtualAllocEx", 10.0},
     {"WriteProcessMemory", 10.0},
     {"OpenProcess", 8.0},
     {"LoadLibraryA", 5.0},
     {"URLDownloadToFile", 8.0},
     {"DeleteService", 8.0},
     {"StartServiceCtrlDispatcher", 8.0},
     {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 5.0},
     {"cmd.exe", 7.0},
     {"powershell.exe", 7.0}
    };

    //transforming bytes to the string
    std::string filecontent(data.begin(), data.end());

    //searching for suspicious strings
    for (const auto& pair : suspiciousStrings) {
        if (filecontent.find(pair.first) != std::string::npos) {

            score += pair.second;
            Logger::instance().log(
                LogLevel::WARNING,
                "Suspicious string found: " + pair.first
            );
        }
    }

    return score;
}

double HeuristicEngine::CheckPEHeader(const pe::Parser& peParser) {
    double score = 0.0;

    //control the entry point offset

    uint32_t entrPointRVA = peParser.getEntryPointRVA();

    bool isEntryPointInCodeSection = false;

    for (const auto& section : peParser.getSections()) {

        if (entrPointRVA >= section.VirtualAddress &&
            entrPointRVA < (section.VirtualAddress + section.Misc_VirtualSize)) {

            //if the section is executable

            if (section.Characteristics & 0x20000000) {// IMAGE_SCN_MEM_EXECUTE

                isEntryPointInCodeSection = true;
            }

            break;
        }
    }

    if (!isEntryPointInCodeSection) {
        score += 20.0;
        Logger::instance().log(
            LogLevel::WARNING,
            "Heuristic: Entry point is not in a executable section."
        );
    }

    //control the section names
    //Unnormal section names are suspicious
    
    for (const auto& section : peParser.getSections()) {
        std::string sectionName(reinterpret_cast<const char*>(section.Name));
        if (sectionName.length() == 0 ||
            sectionName == ".text" ||
            sectionName == ".data" ||
            sectionName == ".rdata" ||
            sectionName == ".rsrc" ||
            sectionName == ".reloc") {
            continue; // Normal section names
        }

        //General suspicious section names:

        if (sectionName == ".upx" || sectionName == "UPX0" || sectionName == "UPX1") {
            score += 15.0; // Packers like UPX
            Logger::instance().log(
                LogLevel::WARNING,
                "Heuristic: Suspicious section name found (packer): " + sectionName
            );
        }
        else {
            score += 5.0; // Other Unnormal names
            Logger::instance().log(
                LogLevel::WARNING,
                "Heuristic: Suspicious section name found: " + sectionName
            );
        }
    }

    //Control the section amount
    // An abnormally large number of sections may indicate a code injection or obfuscation technique.

    if (peParser.getSections().size() > 10) {
        score += 10;
        Logger::instance().log(
            LogLevel::WARNING,
            "Heuristic: Too many sections found (" + std::to_string(peParser.getSections().size()) + ")."
        );
    }

    return score;
}

HeuristicResult HeuristicEngine::analyze(const std::vector<uint8_t>& data) {

    HeuristicResult result;
    double totalScore = 0.0;

    totalScore += checkNOPFlood(data);
    
    double entropy = getEntropy(data);

    if (entropy > 7.0) {

        totalScore += 20.0;
        Logger::instance().log(
            LogLevel::WARNING,
            "Heuristic: High entropy detected. Entropy: " + std::to_string(entropy)
        );
    }

    totalScore += checkSuspiciousStrings(data);

    try {
        pe::Parser peParser(data);
        totalScore += CheckPEHeader(peParser);
    }
    catch (const PeFormatException& e) {
       //it does not affect the heuristic score if it is not a valid PE format.
        Logger::instance().log(LogLevel::INFO, "File is not a valid PE format. PE header analysis skipped.");
    }

    //Make a decision based on your heuristic score
    if (totalScore >= 30.0) {
        result.isSuspicious = true;
        result.score = totalScore;
        result.details = "High heuristic score (" + std::to_string(totalScore) + ") suggests malicious behavior.";
    }
    else if (totalScore > 0) {
        result.isSuspicious = false;
        result.score = totalScore;
        result.details = "Low heuristic score. Potentially benign.";
    }
    else {
        result.isSuspicious = false;
        result.score = 0;
        result.details = "No suspicious behavior detected.";
    }

    return result;
}