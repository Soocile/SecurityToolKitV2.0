
#ifndef SECURITYTOOLKIT_HEURISTICENGINE_H
#define SECURITYTOOLKIT_HEURISTICENGINE_H

#include <vector>
#include <cstdint>
#include <string>
#include"../include/PEParser.hpp"
#include<array>

//holds the heuristic analyze results
struct HeuristicResult {
	bool isSuspicious = false;
	double score = 0.0;
	std::string details;
};


class HeuristicEngine {

public:
	static HeuristicResult analyze(const std::vector<uint8_t>& data);
	

private:

	//Helper Functions
	static double computeEntropyForBuffer(const uint8_t* buf, size_t len);
	static std::string safeSectionName(const IMAGE_SECTION_HEADER& section_header);
	
	static bool contains_utf16le(const std::vector<uint8_t>& data, const std::string& ascii);
	static bool contains_ci_ascii(const std::string& hay, const std::string& needle);

	static double getEntropy(const std::vector<uint8_t>& data);
	static double CheckNOPFlood(const std::vector<uint8_t>& data);
	static double CheckSuspiciousStrings(const std::vector<uint8_t>& data);
	static double CheckImportsWithParser(pe::Parser& parser);
	static double CheckPEHeader(const pe::Parser& peParser, const std::vector<uint8_t>& file_data);

	

	

};




#endif //SECURITYTOOLKIT_HEURISTICENGINE_H