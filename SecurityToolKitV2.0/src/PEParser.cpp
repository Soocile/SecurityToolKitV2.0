
#include"../include/PEParser.hpp"
#include"../include/Logger.hpp"//for logging
#include<string>
#include<iostream>


namespace pe{

	Parser::Parser(const std::vector<uint8_t>& data) : peData(data) {

		if (peData.empty()) {
			Logger::instance().log(LogLevel::ERROR,
				"PEParser: Empty File Data.");
			throw PeFormatException("Empty file Data.");
		}

		//basic controls
		parseDosHeader();
		parseNtHeaders();
		parseSectionHeaders();

	}

	void Parser::parseDosHeader() {

		if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
			throw PeFormatException("File is too small to be a PE file");
		}
		const auto& dosHeader = read<IMAGE_DOS_HEADER>(0);

		//Control the "MZ" Magic Number.
		if (dosHeader.e_magic != 0X5A4D) {//as 'MZ' little endian
			throw PeFormatException("Invalid DOS signature 'MZ'.");
		}


		uint32_t peHeaderOffset = dosHeader.e_lfanew;
		if (peHeaderOffset + sizeof(IMAGE_NT_HEADER32) > peData.size()) {
			throw PeFormatException("Invalid PE header offset.");
		}

	}

	void Parser::parseNtHeaders() {
		const auto& dosHeader = read<IMAGE_DOS_HEADER>(0);
		uint32_t peHeaderOffset = dosHeader.e_lfanew;

		const auto& ntHeaders = read<IMAGE_NT_HEADER32>(peHeaderOffset);

		//control the PE signature
		if (ntHeaders.Signature != 0X00004550) {// 'PE\0\0'
			throw PeFormatException("Invalid PE signature");
		}

		//get the entry point RVA and get the virtual size
		entryPointRVA = ntHeaders.OptionalHeader.AddressOfEntryPoint;
		virtualSize = ntHeaders.OptionalHeader.SizeOfImage;

	}

	void Parser::parseSectionHeaders() {

		const auto& dosHeader = read<IMAGE_DOS_HEADER>(0);
		uint32_t peHeaderOffset = dosHeader.e_lfanew;

		const auto& ntHeaders = read<IMAGE_NT_HEADER32>(peHeaderOffset);

		//calculate the start offset of the section headers
		size_t sectionHeaderOffset = peHeaderOffset + sizeof(IMAGE_NT_HEADER32);

		//READ All section headers

		for (size_t i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {

			if (sectionHeaderOffset + sizeof(IMAGE_SECTION_HEADER) > peData.size()) {
				throw PeFormatException("Section header array is malformed.");
			}
			sections.push_back(read<IMAGE_SECTION_HEADER>(sectionHeaderOffset));
			sectionHeaderOffset += sizeof(IMAGE_SECTION_HEADER);
		}
	}

	size_t Parser::rvaToOffset(uint32_t rva) const {

		for (const auto& section : sections) {

			//find the RVA
			if (rva >= section.VirtualAddress && rva < (section.VirtualAddress + section.Misc_VirtualSize)) {
				// transform RVA to a file offset
				return (rva - section.VirtualAddress) + section.PointerToRawData;
			}
		}

		throw PeFormatException("Invalid RVA: No corresponding section found.");
	}


	uint32_t Parser::getEntryPointRVA() const {
		return entryPointRVA;
	}

	uint32_t Parser::getVirtualSize() const {
		return virtualSize;
	}

	const std::vector<IMAGE_SECTION_HEADER>& Parser::getSections() const {
		return sections;
	}

}