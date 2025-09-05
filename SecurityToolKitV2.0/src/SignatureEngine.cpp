
#include"../include/SignatureEngine.hpp"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <vector>
#include <string>

//starting static members

bool SignatureEngine::isInitialized = false;
std::vector<Sig> SignatureEngine::signatures;
std::once_flag SignatureEngine::initFlag;


//-----------------------------HELPER FUNCTIONS------------------------------

//removes the blanks in the string
static inline void trim(std::string& s) {

	auto notspace = [](unsigned char c) {return !std::isspace(c); };

	s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
	s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
}

// transforms a character to a hex number.
static inline int hexNibble(char c) {

	if (c >= '0' && c <= '9') return c - '0';
	c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
	return -1;

}

bool SignatureEngine::parsePattern(const std::string& s, std::vector<int>& out) {
	out.clear();

	for (size_t i = 0; i < s.size();) {
		char c = s[i];
		if (std::isspace(static_cast<unsigned char>(c))) {
			++i;
			continue;
		}
		//wildcard 

		if (c == '?') {
			if (i + 1 < s.size() && s[i + 1] == '?') {
				out.push_back(-1);
				i += 2;
			}
			else {
				out.push_back(-1);
				i += 1;
			}
			continue;
		}
		int hi = hexNibble(c);
		if (hi < 0) return false;
		if (i + 1 >= s.size()) return false;
		int lo = hexNibble(s[i + 1]);
		if (lo < 0) return false;

		out.push_back(hi << 4 | lo);
		i += 2;
	}

	return !out.empty();
}

bool SignatureEngine::parseConstraint(const std::string& sIn, OffsetConstraint& out) {

	out = {};
	std::string s = sIn;
	trim(s);//clear the blanks
	if (s.empty()) return false;

	//Range: [a-b]

	if (s.front() == '[' && s.back() == ']') {
		std::string body = s.substr(1, s.size() - 2);
		auto dash = body.find('-');
		if (dash == std::string::npos) return false;
		std::string sa = body.substr(0, dash);
		std::string sb = body.substr(dash + 1);
		trim(sa); trim(sb);
		size_t a = 0, b = 0;
		if (!parseUnsigned(sa, a) || !parseUnsigned(sb, b)) return false;
		if (a > b) std::swap(a, b);
		out.type = PosType::Range;
		out.a = a;
		out.b = b;
		return true;
	}


	//Min
	if (s.size() >= 3 && s[0] == '>' && s[1] == '=') {
		std::string sx = s.substr(2);
		trim(sx);
		size_t val = 0;
		if (!parseUnsigned(sx, val)) return false;
		out.type = PosType::Min;
		out.a = val;
		return true;
	}

	//Max
	if (s.size() >= 3 && s[0] == '<' && s[1] == '=') {
		std::string sx = s.substr(2);
		trim(sx);
		size_t val = 0;
		if (!parseUnsigned(sx, val)) return false;
		out.type = PosType::Max;
		out.b = val;
		return true;
	}
//Exact: X
	size_t exact = 0;
	if (!parseUnsigned(s, exact)) return false;
	out.type = PosType::Exact;
	out.a = exact;
	return true;

}

 bool SignatureEngine::parseUnsigned(const std::string& s, size_t& val) {
	
	 if (s.empty()) {
		 val = 0;
		 return false;
	 }
	 //If the text starts with "0x", interpret it as hexadecimal (hex).
	 if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		 try {

			 //std::stoul function , Converts hexadecimal text to numbers.
			 val = std::stoul(s.substr(2), nullptr, 16);
			 return true;

		 }
		 catch (...) {// (...) captures all errors
			 return false;//transform failed
		 }

	 }
	 //if not, try for decimal number
	 try {
		 val = std::stoul(s, nullptr, 10);
		 return true;
	 }
	 catch (...) {// (...) captures all errors
		 return false;//transform failed
	 }

}

 bool SignatureEngine::loadSignatures(const std::string& signatureFile) {

	 std::call_once(initFlag, [&]() {

		 std::ifstream file(signatureFile);
		 if (!file.is_open()) {
			 // Error:file could not open
			 throw std::runtime_error("Failed to open signature file");
			
		 }

		 std::string line;
		 while (std::getline(file, line)) {
			 trim(line);
			 if (line.empty() || line.front() == '#') {
				 continue;
			 }

			 Sig sig;

			 //separate the signature name and pattern
			 auto colon = line.find(':');

			 if (colon == std::string::npos) {
				 continue;//invalid format
			 }

			 sig.name = line.substr(0, colon);
			 trim(sig.name);
			 std::string rest = line.substr(colon + 1);

			 //separate the pattern and the restriction

			 auto at = rest.find('@');
			 std::string patternStr = rest.substr(0, at);
			 trim(patternStr);

			 if (!parsePattern(patternStr, sig.bytes)) {
				 continue;
			 }
			 //check for restriction
			 if (at != std::string::npos) {
				 std::string constraintStr = rest.substr(at + 1);
				 if (!parseConstraint(constraintStr, sig.pos)) {
					 continue;
				 }
			 }

			 signatures.push_back(sig);
		 }

		 isInitialized = true;
		 });
	 return true;

 }

 bool SignatureEngine::matchAt(const std::vector<uint8_t>& data, size_t start, const std::vector<int>& pattern) {

	 //The match is checked in an area the size of the signature pattern.
	 if (start + pattern.size() > data.size()) { return false; };//if the signature pattern is bigger than the file size they cannot match.

	 for (size_t i = 0; i < pattern.size(); ++i) {

		 //widlcard = -1
		 if (pattern[i] == -1) {
			 continue;
		 }


		 //if the byte in the file  does not match with the byte in the signature pattern
		 if (static_cast<uint8_t>(pattern[i]) != data[start + i]) {
			 return false;
		 }
	 }

	 return true;
 }

 bool SignatureEngine::searchAnywhere(const std::vector<uint8_t>& data, const std::vector<int>& pattern) {

	 if (data.size() < pattern.size()) {
		 return false;//if the file size is smaller than the signature size then they cannot match.
	 }

	//scan the file from start to finish
	 for (size_t i = 0; i <= data.size() - pattern.size(); ++i) {
		 // Make Control at every offset
		 if (matchAt(data, i, pattern)) {
			 return true; // matching found, quit.
		 }
	 }

	 return false;
 }

 bool SignatureEngine::searchWithConstraint(
	 const std::vector<uint8_t>& data,
	 const std::vector<int>& pattern,
	 const OffsetConstraint& pos
 ) {
	 switch (pos.type) {
	 case PosType::None: {
		 return searchAnywhere(data, pattern);
	 }

	 case PosType::Exact:

		 // Only control at a exact offset
		 if (pos.a < data.size()) {

			 return matchAt(data, pos.a, pattern);
		 }
		 return false;

	 case PosType::Range:
		 // Scan at a specified range
	 {
		 size_t start = (pos.a < data.size()) ? pos.a : 0;
		 size_t end = (pos.b < data.size()) ? pos.b : data.size();

		 // if the range is not valid
		 if (start >= end || pattern.size() > end - start) {
			 return false;
		 }

		 for (size_t i = start; i <= end - pattern.size(); ++i) {
			 if (matchAt(data, i, pattern)) {
				 return true;
			 }
		 }
	 }
	 return false;

	 case PosType::Min:
		 // Scan at least after that offset
	 {
		 size_t start = (pos.a < data.size()) ? pos.a : 0;
		 if (pattern.size() > data.size() - start) {
			 return false;
		 }

		 for (size_t i = start; i <= data.size() - pattern.size(); ++i) {
			 if (matchAt(data, i, pattern)) {
				 return true;
			 }
		 }
	 }
	 return false;

	 case PosType::Max:
		 // Scan until this offset at most
	 {
		 size_t end = (pos.b < data.size()) ? pos.b : data.size();
		 if (pattern.size() > end) {
			 return false;
		 }

		 for (size_t i = 0; i <= end - pattern.size(); ++i) {
			 if (matchAt(data, i, pattern)) {
				 return true;
			 }
		 }
	 }

	 }
	 return false; // if there is no matching return false;
 }


 bool SignatureEngine::scanFile(
	 const std::vector<uint8_t>& fileData,
	 const std::string& filePath,
	 std::string& detectedThreat
 ) {
	 if (!isInitialized) {
		 return false;
	 }
	  //get in loop with all the loaded signatures 
	 for (const auto& sig : signatures) {
		 
		 if (searchWithConstraint(fileData, sig.bytes, sig.pos)) {
			//matching found!
			 detectedThreat = sig.name;
			 return true;
		 }
	 }

	 //non of the signatures have been matched.
	 return false;
 }

