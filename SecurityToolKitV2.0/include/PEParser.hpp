
// PEParserFull.hpp
// Single-file, header-only, comprehensive PE parser for Windows PE files.
// - Safe bounds-checked reads (memcpy-based).
// - Supports PE32 and PE32+ (x86/x64).
// - Parses: DOS header, NT headers, sections, exports, imports, resources,
//   base relocations, TLS directory, basic debug directory info.
// - Designed for analysis (read-only). Do NOT execute parsed binaries.
// - Usage:
//
//   std::vector<uint8_t> data = readFileToBytes("C:\\Windows\\notepad.exe");
//   pe::Parser parser(data);
//   parser.parseAll(); // or call selective parser methods
//   auto ep = parser.getEntryPointRVA();
//   auto imps = parser.getImports(); // vector of ImportLibrary (structure defined below)
//   auto exps = parser.getExports();
//   auto res  = parser.getResources();
//   // rva->file offset: parser.rvaToOffset(rva)
//
// Notes & Safety:
// - Always test on copies or in a sandbox. This parser reads bytes only.
// - Uses Windows IMAGE_* structures from <windows.h> to avoid struct mismatch.
// - Requires C++17 (for some convenience). No external libs required.

/*
* PE File Structure

DOS HEADER-> legacy, MZ signature
DOS Stub -> basic "this program cannot be run in DOS mode"
PE Signatur-> PE\0\0
File Header -> IMAGE_FILE_HEADER
Optional header-> IMAGE_OPTIONAL_HEADER32/64
Section Headers -> IMAGE_SECTION_HEADER array
Sections-> .text, .data,.rdata,.rsrc ,etc.

*/

#ifndef SECURITYTOOLKIT_PEPARSER_HPP
#define SECURITYTOOLKIT_PEPARSER_HPP


#include <vector>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <cstring>    // memcpy
#include <algorithm>
#include <map>
#include <optional>
#include <sstream>
#include <iomanip>
#include <iostream>   // only for debug printing if you want (not used by parser)
#include <type_traits>
#include<array>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>



namespace pe {
	//speacial exception class for PEParser
	class PeFormatException : public std::runtime_error {
	public:

		explicit PeFormatException(const std::string& msg) : std::runtime_error(msg) {}

	};

	struct ExportEntry {
		uint32_t ordinal; // function ordinal
		uint32_t addressRVA; // RVA of exported function (may be forwarder RVA if pointing to string)
		std::string name;   // optional (may be empty if exported by ordinal only)
	};

	struct ImportFunction {
		// either name (with hint) or ordinal
		bool byOrdinal = false;
		uint16_t hint = 0;//valid if by name
		std::string name;//empty if byOrdinal
		uint16_t ordinal = 0;//valid if byOrdinal
	};

	struct ImportLibrary {
		std::string dllName;
		std::vector<ImportFunction> functions;
	};

	struct ResourceNode {
		// simplified resource node: type/name/lang -> raw data (file offset + size)
	// We will represent nodes as recursive, but store leaf raw blobs.
		std::string path; // combined path like "RT_ICON/ICON_NAME/lang"
		uint32_t dataRVA;
		uint32_t dataSize;
		uint32_t dataOffset; // file offset (computed)
	};

	struct RelocationEntry {
		uint32_t rva;
		uint16_t type; // IMAGE_REL_BASED_* type
	};

	struct TLSInfo {
		uint64_t startAddressOfRawData = 0;
		uint64_t endAddressOfRawData = 0;
		uint64_t addressOfIndex = 0;
		uint64_t addressOfCallbacks = 0;
	};

	class Parser {

	public:
		explicit Parser(const std::vector<uint8_t>& data);

		//High level API
		void parseAll();

		//selective parse functions
		void parseExports();
		void parseImports();
		void parseResources();
		void parseRelocations();
		void parseTLS();
		void parseDebugDirectory();

		//accessors
		uint32_t getEntryPointRVA() const { return entryPointRVA; }
		uint64_t getImageBase() const { return imageBase; }
		bool is64() const { return isPE64; }
		const std::vector<IMAGE_SECTION_HEADER>& getSections() const { return sections; }
		size_t rvaToOffset(uint32_t rva) const; // converts RVA -> file offset (throws if invalid)

		// Results containers (filled by parseX functions)
		std::vector<ExportEntry> exports;
		std::vector<ImportLibrary> imports;
		std::vector<ResourceNode> resources;
		std::vector<RelocationEntry> relocations;
		std::optional<TLSInfo> tlsInfo;
		
	private:

		const std::vector<uint8_t>& peData;

		// basic state
		bool parsedDos = false;
		bool parsedNt = false;
		bool parsedSections = false;
		bool parsedDirectories = false;
		bool isPE64 = false;
		uint32_t entryPointRVA = 0;
		uint64_t imageBase = 0;
		uint32_t sizeOfImage = 0;

		// store NT header offsets to reuse
		uint32_t peHeaderOffset = 0; // e_lfanew
		IMAGE_FILE_HEADER fileHeader{};
		// we'll keep raw optional header copy for both sizes
		IMAGE_OPTIONAL_HEADER32 opt32{};
		IMAGE_OPTIONAL_HEADER64 opt64{};
		IMAGE_DATA_DIRECTORY dataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]{};

		// sections
		std::vector<IMAGE_SECTION_HEADER> sections;

		// ------------------- Low-level safe readers ---------------------------

		template<typename T>
		auto read(size_t offset) const -> decltype(auto) {

			static_assert(std::is_trivially_copyable<T>::value, "read<T>: T must be trivially copyable");

			if (offset + sizeof(T) > peData.size())
				throw pe::PeFormatException("read past end of file");

			alignas(T) std::array<std::uint8_t, sizeof(T)> buffer{};
			std::memcpy(buffer.data(), peData.data() + offset, sizeof(T));

			T result;
			std::memcpy(&result, buffer.data(), sizeof(T));
			return result;
		
	}

		template<typename T>
		requires std::is_same_v<T,uint32_t>
		T read_u32(size_t offset) const {
			constexpr size_t size = sizeof(T);
			if (offset + size > peData.size()) throw PeFormatException("read_u32 past end");

			T value;
			std::memcpy(&value, peData.data() + offset, size);
			return value;
		}

		template<typename T>
		requires std::is_same_v<T, uint16_t>
		T read_u16(size_t offset) const {
			constexpr size_t size = sizeof(T);
			if (offset + size > peData.size()) throw PeFormatException("read_u16 past end");

			T value;
			std::memcpy(&value, peData.data() + offset, size);
			return value;
		}

		// already 1 byte no need std::memcpy
		uint8_t read_u8(size_t offset) const {
			if (offset + 1 > peData.size()) throw PeFormatException("read_u8 past end");
			return peData[offset];
		}
		// Relative virtual addr = virtual addr - ImageBase
		std::string readStringAtRVA(uint32_t rva) const {
			//read null-terminated ASCII string at file offset of rva
			size_t offset = rvaToOffset(rva);
			//find null terminator bounded by file size
			size_t end = offset;
			while (end < peData.size() && peData[end] != 0) ++end;
			return std::string(reinterpret_cast<const char*>(peData.data() + offset), end-offset);
		}


		// ------------------- Parsing small helpers ----------------------------

		void parseDosHeader();
		void parseNtHeaders();
		void parseSectionHeaders();
		void parseDataDirectories();

		//helper to find section for an relative virtual addr
		const IMAGE_SECTION_HEADER* findSectionForRVA(uint32_t rva) const;

		std::optional<size_t> directoryRvaToOffset(DWORD directoryIndex) const;

		// utility: read array of IMAGE_IMPORT_DESCRIPTOR until zeroed descriptor
		std::vector<IMAGE_IMPORT_DESCRIPTOR> readImportDescriptors(size_t offset) const;

		//resource parsing helpers
		void parseResourceDirectoryRecursive(size_t dirOffset, const std::string& pathSoFar);

		// debugging aid (optional): readable section name from header
		static std::string sectionNameToString(const IMAGE_SECTION_HEADER& sh);
			
	};



}



#endif //SECURITYTOOLKIT_PEPARSER_HPP