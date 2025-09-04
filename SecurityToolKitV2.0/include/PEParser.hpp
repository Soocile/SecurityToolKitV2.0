
#ifndef SECURITYTOOLKIT_PEPARSER_HPP
#define SECURITYTOOLKIT_PEPARSER_HPP

#include <vector>
#include <cstdint>
#include <stdexcept>


//speacial exception class for PEParser

class PeFormatException : public std::runtime_error {
public:

	explicit PeFormatException(const std::string& msg) : std::runtime_error(msg) {}

};


namespace pe {

//important structures in PE format

	struct IMAGE_FILE_HEADER {
		uint16_t Machine;
		uint16_t NumberOfSections;
		uint32_t TimeDateStamp;
		uint32_t PointerToSymbolTable;
		uint32_t NumberOfSymbols;
		uint16_t SizeOfOptionalHeader;
		uint16_t Characteristics;
	};

	struct IMAGE_OPTIONAL_HEADER32 {
		uint16_t Magic;
		// ... (Diðer alanlar)
		uint32_t AddressOfEntryPoint;
		uint32_t BaseOfCode;
		uint32_t BaseOfData;
		uint32_t ImageBase;
		uint32_t SectionAlignment;
		uint32_t FileAlignment;
		// ... (Diðer alanlar)
		uint32_t SizeOfImage;
		// ... (Diðer alanlar)
	};

	struct IMAGE_DOS_HEADER {
		uint16_t e_magic; //magic number("MZ")
		//other fields
		uint32_t e_lfanew; //offset to the PE Header
};

	struct IMAGE_NT_HEADER32 {
		uint32_t Signature;//PE signature
		IMAGE_FILE_HEADER  FileHeader;
		IMAGE_OPTIONAL_HEADER32 OptionalHeader;
	
	};

	struct IMAGE_SECTION_HEADER {

		uint8_t Name[8];
		uint32_t Misc_VirtualSize;
		uint32_t VirtualAddress;
		uint32_t SizeOfRawData;
		uint32_t PointerToRawData;
		uint32_t Characteristics;

	};


	class Parser {

	public:
		// Constructor: Takes the raw PE data and starts parsing it.
		explicit Parser(const std::vector<uint8_t>& data);

		size_t rvaToOffset(uint32_t rva) const;

		//returns the virtual memory size
		uint32_t getVirtualSize() const;

		//returns the Entry Point's RVA
		uint32_t getEntryPointRVA() const;

		//returns section headers
		const std::vector<IMAGE_SECTION_HEADER>& getSections() const;

	private:
		
		const std::vector<uint8_t>& peData;
		std::vector<IMAGE_SECTION_HEADER> sections;
		uint32_t entryPointRVA = 0;
		uint32_t virtualSize = 0;

		//Helper parse functions
		void parseDosHeader();
		void parseNtHeaders();
		void parseSectionHeaders();


		template<typename T>
		T read(size_t offset) const {
			if (offset + sizeof(T) > peData.size()) {
				throw PeFormatException("read past end of file");
			}
			
			return *reinterpret_cast<const T*>(peData.data() + offset);
		}
	};



}



#endif //SECURITYTOOLKIT_PEPARSER_HPP