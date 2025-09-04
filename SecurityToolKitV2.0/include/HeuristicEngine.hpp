
#ifndef SECURITYTOOLKIT_HEURISTICENGINE_H
#define SECURITYTOOLKIT_HEURISTICENGINE_H

#include <vector>
#include <cstdint>
#include <string>
#include"../include/PEParser.hpp"

//holds the heuristic analyze results
struct HeuristicResult {
	bool isSuspicious = false;
	double score = 0.0;
	std::string details;
};


class HeuristicEngine {

public:

	//makes heuristic analyze using the bytes on a file
	static HeuristicResult analyze(const std::vector<uint8_t>& fileData);

private:

	//Helper Functions
	static double getEntropy(const std::vector<uint8_t>& data);
	static double checkNOPFlood(const std::vector<uint8_t>& data);
	static double checkSuspiciousStrings(const std::vector<uint8_t>& data);
	static double CheckPEHeader(const pe::Parser& peParser);


	//Threshold values ​​for heuristic scoring
	static constexpr double ENTROPY_THRESHOLD = 7.5;
	static constexpr double NOPFLOOD_THRESHOLD = 0.5;
	static constexpr double MAX_SCORE = 100.0;

};




#endif //SECURITYTOOLKIT_HEURISTICENGINE_H