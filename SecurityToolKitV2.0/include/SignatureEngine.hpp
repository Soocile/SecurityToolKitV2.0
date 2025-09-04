
#ifndef SECURITYTOOLKIT_SIGNATUREENGINE_HPP

#define SECURITYTOOLKIT_SIGNATUREENGINE_HPP

#include <string>
#include <vector>
#include <fstream>
#include <limits>
#include <cstdint>

//a restriction type on the signature file
enum class PosType {
	None,//no restriction (it could be anywhere in the signatures.txt)
	Exact,//at the exact location
	Range,//at a specified range
	Min,//at least after that location
	Max//at most until this location

};


//offset restriction for a signature
struct OffsetConstraint {
	PosType type = PosType::None;
	size_t a = 0;
	size_t b = 0;

};

//a signature pattern and name
struct Sig {
	std::string name;
	std::vector<int> bytes;
	OffsetConstraint pos;
};

class SignatureEngine {
public:

	//loads the signature file
	static bool loadSignatures(const std::string& signatureFile);

	//scans a file for signatures
	static bool scanFile(const std::vector<uint8_t>& fileData, const std::string& filePath, std::string& detectedThreat);

private:
	static bool isInitialized;
	static std::vector<Sig> signatures;

	//Helper functions
	static bool parseUnsigned(const std::string& s, size_t& val);
	static bool parsePattern(const std::string& s, std::vector<int>& out);
	static bool parseConstraint(const std::string& sIn, OffsetConstraint& out);

	//matching functions
	static bool matchAt(const std::vector<uint8_t>& data, size_t start, const std::vector<int>& pattern);
	static bool searchAnywhere(const std::vector<uint8_t>& data, const std::vector<int>& pattern);
	static bool searchWithConstraint(const std::vector<uint8_t>& data, const std::vector<int>& pattern, const OffsetConstraint& pos);


};



#endif // SECURITYTOOLKIT_SIGNATUREENGINE_HPP