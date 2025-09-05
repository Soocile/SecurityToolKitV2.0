
#include"../include/HeuristicEngine.hpp"
#include"../Logger.hpp"

#undef min

#include <map>
#include <cmath>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>

#undef max


// ---------- Helper utilities ----------

 double HeuristicEngine::computeEntropyForBuffer(const uint8_t* buf, size_t len) {

	if (len == 0) return 0.0;

	std::array<uint32_t, 256> counts{};
	counts.fill(0);

	for (size_t i = 0; i < len; ++i) counts[buf[i]]++;

	double entropy = 0.0;
	const double N = static_cast<double>(len);

	for (int i = 0; i < 256; ++i) {
		if (counts[i] == 0) continue;
		double p = static_cast<double>(counts[i]) / N;
		entropy -= p * std::log2(p);//Shannon's entropy formula
	}
	return entropy;
}

 std::string HeuristicEngine::safeSectionName(const IMAGE_SECTION_HEADER& s) {

	const char* p = reinterpret_cast<const char*>(s.Name);
	size_t len = 0;
	while (len < 8 && p[len] != '\0') ++len;
	return std::string(p, len);
}

// Case-insensitive find for ASCII in a std::string
 bool HeuristicEngine::contains_ci_ascii(const std::string& hay, const std::string& needle) {
	if (needle.empty() || hay.size() < needle.size()) return false;
	// make lower once? but faster to do find with transform on the fly
	std::string lower_hay; lower_hay.resize(hay.size());

	std::transform(hay.begin(), hay.end(), lower_hay.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

	std::string lower_need; lower_need.resize(needle.size());
	std::transform(needle.begin(), needle.end(), lower_need.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

	return lower_hay.find(lower_need) != std::string::npos;
}

// check for UTF-16LE presence of an ASCII string (very common in PE resources/strings)
 bool HeuristicEngine::contains_utf16le(const std::vector<uint8_t>& data, const std::string& ascii) {
	if (ascii.empty()) return false;
	// pattern: e.g. 'C' 0x00 'r' 0x00 ...
	size_t n = ascii.size();
	if (data.size() < 2 * n) return false;
	for (size_t i = 0; i + 2 * n <= data.size(); ++i) {
		bool ok = true;
		for (size_t j = 0; j < n; ++j) {
			if (data[i + j * 2] != static_cast<uint8_t>(ascii[j]) || data[i + j * 2 + 1] != 0x00) { ok = false; break; }
		}
		if (ok) return true;
	}
	return false;
}

// ---------- HeuristicEngine methods ----------

double HeuristicEngine::getEntropy(const std::vector<uint8_t>& data) {
	if (data.empty()) return 0.0;
	return computeEntropyForBuffer(data.data(), data.size());
}

double HeuristicEngine::CheckNOPFlood(const std::vector<uint8_t>& data) {

	// Returns a heuristic *score* (0..20) based on density and runs of NOP-like bytes.
	if (data.empty()) return 0.0;

	size_t total = data.size();
	size_t suspiciousCount = 0;
	size_t maxRun = 0;
	size_t curRun = 0;

	auto isSuspByte = [](uint8_t b)->bool {
		return b == 0x90 || b == 0xCC || b == 0xF4; // NOP, INT3, HLT
		};


	for (size_t i = 0; i < total; ++i) {
		if (isSuspByte(data[i])) {
			suspiciousCount++;
			curRun++;
		}
		else {
			// also check 2-byte constructs e.g. EB FE, EB 01 by peeking previous byte pairs
			if (i > 0) {
				uint8_t a = data[i - 1];
				uint8_t b = data[i];
				if ((a == 0xEB && b == 0xFE) || (a == 0xEB && b == 0x01)) {
					// count as part of suspicious run (we already may have counted them individually)
					// ensure curRun increment (but don't double count)
					// Simple approach: treat these as suspicious pair markers by artificially boosting curRun
					curRun += 1;
					suspiciousCount += 1;
				}
			}
			if (curRun > maxRun) maxRun = curRun;
			curRun = 0;
		}
	}
	if (curRun > maxRun) maxRun = curRun;

	double ratio = static_cast<double>(suspiciousCount) / static_cast<double>(total); // 0..1
	// Score policy: small ratios are fine; larger ratios => bigger score.
	// Map ratio to 0..12 score; add bonus if there is a very long run (>64)
	double score = std::min(12.0, ratio * 200.0); // e.g. ratio 0.05 => 10
	if (maxRun > 64) score += 6.0; // contiguous filler segment -> big suspicion
	if (score > 18.0) score = 18.0;
	return score;

}

double HeuristicEngine::CheckSuspiciousStrings(const std::vector<uint8_t>& data) {
	
	//  - ASCII, case-insensitive search for suspicious API names
	//  - UTF-16LE search for same strings (common in resources/imports)
	//  - Score weighting per string
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

	// transform bytes -> ASCII string for quick search (non-printable become dot)
	std::string ascii;
	ascii.reserve(data.size());
	for (uint8_t b : data) {
		ascii.push_back(static_cast<char>(b));
	}

	for (const auto& kv : suspiciousStrings) {
		const std::string& needle = kv.first;
		double w = kv.second;
		bool found = false;
		// ascii case-insensitive
		if (contains_ci_ascii(ascii, needle)) found = true;
		// unicode (utf-16le) pattern:
		if (!found && contains_utf16le(data, needle)) found = true;
		if (found) {
			score += w;
			Logger::instance().log(LogLevel::WARNING, "Suspicious string/import candidate found: " + needle);
		}
	}

	return score;
}

double HeuristicEngine::CheckImportsWithParser(pe::Parser& parser) {
	// Try to parse imports (parser may throw)
	double score = 0.0;
	try {
		parser.parseImports(); // Parser implementation populates parser.imports
		for (const auto& lib : parser.imports) {
			// Commonly abused APIs
			for (const auto& fn : lib.functions) {
				std::string fname = fn.byOrdinal ? ("#" + std::to_string(fn.ordinal)) : fn.name;
				// lower-case simple
				std::string fname_l = fname;
				std::transform(fname_l.begin(), fname_l.end(), fname_l.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

				if (fname_l.find("createremotethread") != std::string::npos ||
					fname_l.find("writeprocessmemory") != std::string::npos ||
					fname_l.find("virtualallocex") != std::string::npos ||
					fname_l.find("openprocess") != std::string::npos) {
					score += 12.0;
					Logger::instance().log(LogLevel::WARNING, "Import heuristic: suspicious imported function: " + fname + " from " + lib.dllName);
				}
				else if (fname_l.find("urldownloadtofile") != std::string::npos ||
					fname_l.find("shellexecute") != std::string::npos ||
					fname_l.find("loadlibrary") != std::string::npos) {
					score += 6.0;
					Logger::instance().log(LogLevel::WARNING, "Import heuristic: network / loader function: " + fname + " from " + lib.dllName);
				}
			}
		}
	}
	catch (const pe::PeFormatException& ) {
		// parser couldn't parse imports — ignore (we already log elsewhere)
	}
	// cap reasonable
	if (score > 30.0) score = 30.0;
	return score;
}



// ---------- PE header checks (main improvement) ----------
// NOTE: signature changed: now takes parser AND the raw file bytes to compute overlay and section-bytes entropy.
double HeuristicEngine::CheckPEHeader(const pe::Parser& peParser, const std::vector<uint8_t>& fileData) {
	double score = 0.0;

	// 1) EntryPoint location
	try {
		uint32_t entryRVA = peParser.getEntryPointRVA();
		bool entryInExecSection = false;
		uint32_t lastSectionRawEnd = 0;

		for (const auto& section : peParser.getSections()) {
			// safe virtual size: use union field
			uint32_t vsize = section.Misc.VirtualSize;
			uint32_t rawSize = section.SizeOfRawData;
			uint32_t covered = std::max(vsize, rawSize);

			// track raw end to detect overlays later
			uint32_t rawEnd = section.PointerToRawData + rawSize;
			if (rawEnd > lastSectionRawEnd) lastSectionRawEnd = rawEnd;

			if (entryRVA >= section.VirtualAddress && entryRVA < (section.VirtualAddress + covered)) {
				// check execute flag
				if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
					entryInExecSection = true;
				}
				break;
			}
		}

		if (!entryInExecSection) {
			score += 25.0;
			Logger::instance().log(LogLevel::WARNING, "Heuristic: Entry point not in an executable section.");
		}

		// 2) Overlay detection (file size after last section raw end)
		size_t fileSize = fileData.size();
		if (fileSize > lastSectionRawEnd + 16) { // allow small alignment/PAD
			size_t overlaySize = fileSize - lastSectionRawEnd;
			double overlayScore = std::min(10.0, static_cast<double>(overlaySize) / 1024.0); // 1 point per KB up to 10
			Logger::instance().log(LogLevel::INFO, "Overlay detected: " + std::to_string(overlaySize) + " bytes.");
			score += overlayScore;
		}

		// 3) Section name & count checks + packer detection and section entropy
		size_t sectionCount = peParser.getSections().size();
		if (sectionCount > 15) {
			score += 10.0;
			Logger::instance().log(LogLevel::WARNING, "Heuristic: High section count: " + std::to_string(sectionCount));
		}

		for (const auto& section : peParser.getSections()) {
			std::string sname = safeSectionName(section);
			if (sname.empty() || sname == ".text" || sname == ".data" || sname == ".rdata" || sname == ".rsrc" || sname == ".reloc") {
				// normal
			}
			else if (sname == ".upx" || sname == "UPX0" || sname == "UPX1") {
				score += 18.0;
				Logger::instance().log(LogLevel::WARNING, "Heuristic: UPX/packer section: " + sname);
			}
			else {
				// suspicious other names
				score += 5.0;
				Logger::instance().log(LogLevel::WARNING, "Heuristic: Unusual section name: " + sname);
			}

			// per-section entropy (use raw data)
			uint32_t rawSize = section.SizeOfRawData;
			uint32_t rawPtr = section.PointerToRawData;
			if (rawSize > 0 && rawPtr + rawSize <= fileData.size()) {
				double ent = computeEntropyForBuffer(fileData.data() + rawPtr, rawSize);
				if (ent > 7.5) {
					score += 10.0; // high entropy -> possibly packed/encrypted code
					Logger::instance().log(LogLevel::WARNING, "Heuristic: High entropy in section " + sname + " -> " + std::to_string(ent));
				}
				else if (ent > 6.5) {
					score += 3.0; // suspicious but not definitive
				}
			}
		}

		// 4) Import-based heuristics (call parser to get imports)
		{
			// Need non-const parser for parseImports; try to cast away const or ask caller to pass non-const.
			// Safer: rely on parser.parseImports which was non-const in our Parser — so we will const_cast.
			try {
				pe::Parser& pnon = const_cast<pe::Parser&>(peParser);
				double impScore = CheckImportsWithParser(pnon);
				score += impScore;
			}
			catch (...) {
				Logger::instance().log(LogLevel::INFO,
					"PE header analysis skipped (invalid PE).");
				return 0.0;
			}
		}

	}
	catch (const pe::PeFormatException& e) {
		Logger::instance().log(LogLevel::INFO, "PE header analysis skipped (invalid PE).");
		return 0.0;
	}

	return score;
}

HeuristicResult HeuristicEngine::analyze(const std::vector<uint8_t>& data) {

	HeuristicResult result;
	double totalScore = 0.0;

	// 1) NOP flood -> returns a heuristic score
	totalScore += CheckNOPFlood(data);

	// 2) Whole-file entropy
	double entropy = getEntropy(data);
	if (entropy > 7.0) {
		totalScore += 22.0;
		Logger::instance().log(LogLevel::WARNING, "Heuristic: High global entropy detected. Entropy: " + std::to_string(entropy));
	}
	else if (entropy > 6.5) {
		totalScore += 6.0;
	}

	// 3) Suspicious strings (ASCII + UTF-16LE)
	totalScore += CheckSuspiciousStrings(data);

	// 4) PE Header related heuristics (uses Parser + file data)
	try {
		pe::Parser peParser(data);
		// call our new signature that accepts file bytes
		totalScore += CheckPEHeader(peParser, data);
	}
	catch (const pe::PeFormatException& ) {
		// not a PE -> no PE heuristics
		Logger::instance().log(LogLevel::INFO, "File is not a valid PE format. PE header analysis skipped.");
	}

	// Decision thresholds — tuned conservatively
	if (totalScore >= 40.0) {
		result.isSuspicious = true;
		result.score = totalScore;
		result.details = "High heuristic score (" + std::to_string(totalScore) + ") suggests malicious behavior.";
	}
	else if (totalScore >= 15.0) {
		result.isSuspicious = false;
		result.score = totalScore;
		result.details = "Low-to-moderate heuristic score (" + std::to_string(totalScore) + "). Review recommended.";
	}
	else {
		result.isSuspicious = false;
		result.score = totalScore;
		result.details = "No suspicious behavior detected.";
	}

	return result;
}
