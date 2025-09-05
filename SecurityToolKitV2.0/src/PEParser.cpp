
#include"../include/PEParser.hpp"
#include"../include/Logger.hpp"//for logging
#include<string>
#include<iostream>

#undef max
#undef ERROR


namespace pe {

	inline void Parser::parseDosHeader() {

		if (parsedDos) return;
		constexpr size_t dosHeaderSize = sizeof(IMAGE_DOS_HEADER);

		if (peData.size() < dosHeaderSize) throw PeFormatException("file too small for DOS header");

		IMAGE_DOS_HEADER dos = read<IMAGE_DOS_HEADER>(0);

		if (dos.e_magic != IMAGE_DOS_SIGNATURE) throw PeFormatException("Invalid MZ signature");

		if (dos.e_lfanew <= 0 || static_cast<size_t>(dos.e_lfanew) >= peData.size()) {
			throw PeFormatException("Invalid e_lfanew");
		}

		peHeaderOffset = static_cast<uint32_t>(dos.e_lfanew);
		parsedDos = true;
	}

	inline void Parser::parseNtHeaders() {

		if (parsedNt) return;
		if (!parsedDos) parseDosHeader();

		//signature
		if (peHeaderOffset + sizeof(uint32_t) > peData.size()) throw PeFormatException("PE header offset beyond file");
		uint32_t signature = read_u32<uint32_t>(peHeaderOffset);

		if (signature != IMAGE_NT_SIGNATURE) throw PeFormatException("Invalid PE signature");

		//file header
		size_t fileHeaderoffset = peHeaderOffset + sizeof(uint32_t);

		if (fileHeaderoffset + sizeof(IMAGE_FILE_HEADER) > peData.size()) throw PeFormatException("file header out of range");

		fileHeader = read<IMAGE_FILE_HEADER>(fileHeaderoffset);

		//optional header offset
		size_t optionalOffset = fileHeaderoffset + sizeof(IMAGE_FILE_HEADER);

		if (optionalOffset + sizeof(uint16_t) > peData.size()) throw PeFormatException("optional header missing magic");

		uint16_t magic = read_u16<uint16_t>(optionalOffset);

		if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			isPE64 = true;

			if (optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER64) > peData.size()) throw PeFormatException("optional header64 truncated");

			opt64 = read<IMAGE_OPTIONAL_HEADER64>(optionalOffset);
			entryPointRVA = opt64.AddressOfEntryPoint;
			imageBase = opt64.ImageBase;
			sizeOfImage = opt64.SizeOfImage;
			//copy data directories
			for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
				dataDirectory[i] = opt64.DataDirectory[i];
			}

		}
		else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			isPE64 = false;
			if (optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER32) > peData.size()) throw PeFormatException("optional header32 truncated");

			opt32 = read<IMAGE_OPTIONAL_HEADER32>(optionalOffset);
			entryPointRVA = opt32.AddressOfEntryPoint;
			imageBase = opt32.ImageBase;
			sizeOfImage = opt32.SizeOfImage;

			//copy data directories as well
			for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
				dataDirectory[i] = opt64.DataDirectory[i];
			}
		}
		else {
			throw PeFormatException("Unknown optional header magic");
		}

		parsedNt = true;
	}

	inline void Parser::parseSectionHeaders() {

		if (parsedSections) return;
		if (!parsedNt) parseNtHeaders();
		// section headers start = peHeaderOffset + 4 + sizeof(FILE_HEADER) + SizeOfOptionalHeader

		size_t sectionOffset = peHeaderOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;

		if (sectionOffset > peData.size()) throw PeFormatException("section header offset beyond file");

		sections.clear();
		for (unsigned i = 0; i < fileHeader.NumberOfSections; ++i) {

			if (sectionOffset + sizeof(IMAGE_SECTION_HEADER) > peData.size())  throw PeFormatException("section header truncated");

			IMAGE_SECTION_HEADER section_header = read<IMAGE_SECTION_HEADER>(sectionOffset);
			sections.push_back(section_header);
			sectionOffset += sizeof(IMAGE_SECTION_HEADER);
		}
		parsedSections = true;
	}

	inline size_t Parser::rvaToOffset(uint32_t rva) const {
		// If rva is inside headers region (before first section), return rva if within SizeOfHeaders
   // But safer to map via sections; some files may put data in header.

		const IMAGE_SECTION_HEADER* section_header = findSectionForRVA(rva);

		if (section_header) {

			uint32_t delta = rva - section_header->VirtualAddress; //delta = relative virtual addr - virtual addr
			uint32_t ptr = section_header->PointerToRawData + delta;

			if (ptr > peData.size()) throw PeFormatException("rvaToOffset calculated beyond file");

			return static_cast<size_t>(ptr);

		}
		// If no section matched, try if it's within headers (rare)
	// For safety: if rva < SizeOfHeaders (optional header field) map to same offset

		uint32_t headersSize = isPE64 ? opt64.SizeOfHeaders : opt32.SizeOfHeaders;

		if (rva < headersSize && rva < peData.size()) {

			return static_cast<size_t>(rva);
		}

		throw PeFormatException("Invalid RVA: no corresponding section");
	}

	// ------------------ Export parsing --------------------------------------

	inline void Parser::parseExports() {

		exports.clear();
		if (!parsedDirectories) parseDataDirectories();
		auto opt = directoryRvaToOffset(IMAGE_DIRECTORY_ENTRY_EXPORT);
		if (!opt) return; // no exports

		size_t exportsOffset = *opt; // opt.value() *-> *opt

		if (exportsOffset + sizeof(IMAGE_EXPORT_DIRECTORY) > peData.size()) return;

		IMAGE_EXPORT_DIRECTORY export_directory = read<IMAGE_EXPORT_DIRECTORY>(exportsOffset);

		// arrays are RVAs -> convert to offsets
		uint32_t namePtrRVA = export_directory.AddressOfNames;
		uint32_t ordPtrRVA = export_directory.AddressOfNameOrdinals;
		uint32_t funcPtrRVA = export_directory.AddressOfFunctions;

		if (namePtrRVA == 0 || funcPtrRVA == 0) {
			// no exported names (maybe only by ordinal or none)
			// handle functions by ordinal if needed
		}

		//read arrays
		size_t namePtrOffset = (namePtrRVA ? rvaToOffset(namePtrRVA) : 0);
		size_t ordPtrOffset = (ordPtrRVA ? rvaToOffset(ordPtrRVA) : 0);
		size_t funcPtrOffset = (funcPtrRVA ? rvaToOffset(funcPtrRVA) : 0);

		// functions array length = ed.NumberOfFunctions; names count = ed.NumberOfNames

		for (uint32_t i = 0; i < export_directory.NumberOfNames; ++i) {

			uint32_t nameRVA = read_u32<uint32_t>(namePtrOffset + i * 4);
			std::string name = readStringAtRVA(nameRVA);

			// ordinal (index into functions array) is at ordPtrOffset + i*2
			uint16_t ordinalIndex = read_u16<uint16_t>(ordPtrOffset + i * 2);
			uint32_t funcRVA = read_u32<uint32_t>(funcPtrOffset + ordinalIndex * 4);
			ExportEntry export_entry;
			export_entry.name = name;
			export_entry.ordinal = static_cast<uint32_t>(export_directory.Base) + ordinalIndex;
			export_entry.addressRVA = funcRVA;
			exports.push_back(export_entry);
		}
		//Also, there can be some functions that exported only by ordinal but not named.

		for (uint32_t i = 0; i < export_directory.NumberOfFunctions; ++i) {
			bool alreadyParsed = std::any_of(exports.begin(), exports.end(), [&](const ExportEntry& e) {
				return e.ordinal == export_directory.Base + i;
				});
			if (alreadyParsed) continue;

			uint32_t funcRVA = read_u32<uint32_t>(funcPtrOffset + i * sizeof(uint32_t));
			ExportEntry export_entry;
			export_entry.name = ""; // unnamed
			export_entry.ordinal = export_directory.Base + i;
			export_entry.addressRVA = funcRVA;
			exports.push_back(export_entry);
		}

	}


	//------------------ Import parsing --------------------------------------

	inline std::vector<IMAGE_IMPORT_DESCRIPTOR> Parser::readImportDescriptors(size_t offset) const {

		std::vector<IMAGE_IMPORT_DESCRIPTOR> list;

		size_t cur = offset;

		while (true) {

			if (cur + sizeof(IMAGE_IMPORT_DESCRIPTOR) > peData.size()) throw PeFormatException("import descriptor truncated");

			IMAGE_IMPORT_DESCRIPTOR import_descrp = read<IMAGE_IMPORT_DESCRIPTOR>(cur);

			//terminator : all zeroes
			if (import_descrp.Characteristics == 0 && import_descrp.FirstThunk == 0 && import_descrp.Name == 0
				&& import_descrp.OriginalFirstThunk == 0) break;
			list.push_back(import_descrp);

			cur += sizeof(IMAGE_IMPORT_DESCRIPTOR);

		}
		return list;

	}

	inline void Parser::parseImports() {

		imports.clear();
		if (!parsedDirectories) parseDataDirectories();
		auto opt = directoryRvaToOffset(IMAGE_DIRECTORY_ENTRY_IMPORT);
		if (!opt) return;

		size_t impOffset = *opt; //opt.value()
		auto descriptors = readImportDescriptors(impOffset);

		for (const auto& desc : descriptors) {
			uint32_t nameRVA = desc.Name;
			std::string dll = readStringAtRVA(nameRVA);
			ImportLibrary lib;
			lib.dllName = dll;

			//choose which thunk to read : OriginalFirstThunk (Characteristics) preferred, else FirstThunk

			uint32_t thunkRVA = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
			if (thunkRVA == 0) {
				imports.push_back(lib);
				continue;
			}

			size_t thunkOffset = rvaToOffset(thunkRVA);
			// Thunks are arrays of IMAGE_THUNK_DATA (size depends on 32/64)
			size_t thunkEntrySize = isPE64 ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);
			size_t cur = thunkOffset;

			while (true) {

				if (cur + thunkEntrySize > peData.size()) break;

				uint64_t rawThunk;

				if (isPE64) rawThunk = read<uint64_t>(cur);
				else rawThunk = read<uint32_t>(cur);
				if (rawThunk == 0) break;
				ImportFunction function;

				// If highest bit set -> ordinal import
				if (isPE64) {
					// IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
					if (rawThunk & IMAGE_ORDINAL_FLAG64) {

						function.byOrdinal = true;
						function.ordinal = static_cast<uint16_t>(rawThunk & 0xFFFF);

					}
					else {

						uint32_t nameRVA2 = static_cast<uint32_t>(rawThunk & 0xFFFFFFFF);
						size_t nameOffset = rvaToOffset(nameRVA2);
						uint16_t hint = read_u16<uint16_t>(nameOffset);

						std::string fname(reinterpret_cast<const char*>(peData.data() + nameOffset + 2));

						function.byOrdinal = false;
						function.hint = hint;
						function.name = fname;

					}

				}
				else {
					// IMAGE_ORDINAL_FLAG32 = 0x80000000
					if (rawThunk & IMAGE_ORDINAL_FLAG32) {

						function.byOrdinal = true;
						function.ordinal = static_cast<uint16_t>(rawThunk & 0XFFFF);
					}
					else {

						uint32_t nameRVA2 = static_cast<uint32_t>(rawThunk & 0xFFFFFFFF);
						size_t nameOffset = rvaToOffset(nameRVA2);
						uint16_t hint = read_u16<uint16_t>(nameOffset);
						std::string fname(reinterpret_cast<const char*>(peData.data() + nameOffset + 2));
						function.byOrdinal = false;
						function.hint = hint;
						function.name = fname;
					}


				}

				lib.functions.push_back(function);
				cur += thunkEntrySize;


			}
			imports.push_back(lib);
		}
	}
	// ------------------ Resource parsing ------------------------------------


	inline void Parser::parseResources() {

		resources.clear();
		if (!parsedDirectories) parseDataDirectories();

		auto opt = directoryRvaToOffset(IMAGE_DIRECTORY_ENTRY_RESOURCE);

		if (!opt) return;

		size_t rootOffset = *opt;

		// Start recursive traversal with empty path
		parseResourceDirectoryRecursive(rootOffset, "");
	}

	// helper: parse a resource directory recursively

	inline void Parser::parseResourceDirectoryRecursive(size_t dirOffset, const std::string& pathSoFar) {

		if (dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) > peData.size()) throw PeFormatException("resource dir truncated");
		IMAGE_RESOURCE_DIRECTORY rd = read<IMAGE_RESOURCE_DIRECTORY>(dirOffset);

		uint32_t numberOfEntries = rd.NumberOfNamedEntries + rd.NumberOfIdEntries;
		size_t entryOffset = dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);

		for (uint32_t i = 0; i < numberOfEntries; ++i) {

			if (entryOffset + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > peData.size()) throw PeFormatException("resource entry truncated");
			IMAGE_RESOURCE_DIRECTORY_ENTRY dir_entry = read<IMAGE_RESOURCE_DIRECTORY_ENTRY>(entryOffset);

			bool isDirectory = (dir_entry.DataIsDirectory != 0);
			std::string namePart;

			if (dir_entry.NameIsString) {

				// Name is a RVA to unicode string (WORD length followed by WCHARs)
				uint32_t nameRVA = dir_entry.NameOffset;
				size_t nameOffset = rvaToOffset(nameRVA);
				uint16_t len = read_u16<uint16_t>(nameOffset);
				// read wide chars and convert to narrow (basic)
				std::u16string u16;
				u16.reserve(len);
				for (uint16_t k = 0; k < len; ++k) {
					uint16_t wc = read_u16<uint16_t>(nameOffset + 2 + k * 2);
					u16.push_back(static_cast<char16_t>(wc));
				}
				//convert naive 
				std::string conv;
				conv.reserve(len);
				for (char16_t wc : u16) conv.push_back(static_cast<char>(wc & 0xFF));
				namePart = conv;
			}
			else {
				// ID is in Id
				namePart = std::to_string(dir_entry.Id);
			}
			// compute next offset
			if (isDirectory) {
				//we have not reached data yet
				uint32_t dirRVA = dir_entry.OffsetToDirectory;
				size_t subdirOffset = rvaToOffset(dirRVA);
				std::string nextPath = pathSoFar.empty() ? namePart : (pathSoFar + "/" + namePart);
				parseResourceDirectoryRecursive(subdirOffset, nextPath);
			}
			else {
				//Data entry

				uint32_t dataentryRVA = dir_entry.OffsetToDirectory;

				size_t dataentryoffset = rvaToOffset(dataentryRVA);

				if (dataentryoffset + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > peData.size()) throw PeFormatException("resource data entry truncated");
				IMAGE_RESOURCE_DATA_ENTRY rde = read<IMAGE_RESOURCE_DATA_ENTRY>(dataentryoffset);
				// rde.OffsetToData is RVA to raw data

				ResourceNode rn;
				rn.path = pathSoFar.empty() ? namePart : (pathSoFar + "/" + namePart);
				rn.dataRVA = rde.OffsetToData;
				rn.dataSize = rde.Size;
				// compute file offset for convenience (may throw)
				rn.dataOffset = static_cast<uint32_t>(rvaToOffset(rn.dataRVA));
				resources.push_back(rn);
			}

			entryOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
		}


	}
	// ------------------ Relocation parsing ----------------------------------

	inline void Parser::parseRelocations() {

		relocations.clear();
		if (!parsedDirectories) parseDataDirectories();
		auto opt = directoryRvaToOffset(IMAGE_DIRECTORY_ENTRY_BASERELOC);
		if (!opt) return;

		size_t baseRelocOffset = *opt;
		size_t cur = baseRelocOffset;

		while (cur + sizeof(IMAGE_BASE_RELOCATION) <= peData.size()) {
			IMAGE_BASE_RELOCATION br = read<IMAGE_BASE_RELOCATION>(cur);
			if (br.SizeOfBlock == 0) break;

			size_t entriesStart = cur + sizeof(IMAGE_BASE_RELOCATION);
			size_t bytesOfEntries = br.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
			size_t entries_count = bytesOfEntries / sizeof(uint16_t);

			for (size_t i = 0; i < entries_count; ++i) {

				uint16_t entry = read_u16<uint16_t>(entriesStart + i * 2);
				uint16_t type = entry >> 12;
				uint16_t offset = entry & 0X0FFF;
				RelocationEntry relocation;

				relocation.rva = br.VirtualAddress + offset;
				relocation.type = type;
				relocations.push_back(relocation);

			}
			cur += br.SizeOfBlock;
		}

	}

	// ------------------ TLS parsing -----------------------------------------

	inline void Parser::parseTLS() {

		tlsInfo.reset();

		if (!parsedDirectories) parseDataDirectories();
		auto opt = directoryRvaToOffset(IMAGE_DIRECTORY_ENTRY_TLS);
		if (!opt) return;

		size_t tlsOffset = *opt;

		if (isPE64) {

			if (tlsOffset + sizeof(IMAGE_TLS_DIRECTORY64) > peData.size()) throw PeFormatException("tls truncated");
			IMAGE_TLS_DIRECTORY64 t_64 = read<IMAGE_TLS_DIRECTORY64>(tlsOffset);

			TLSInfo tlsinfo;

			tlsinfo.startAddressOfRawData = t_64.StartAddressOfRawData;
			tlsinfo.endAddressOfRawData = t_64.EndAddressOfRawData;
			tlsinfo.addressOfIndex = t_64.AddressOfIndex;
			tlsinfo.addressOfCallbacks = t_64.AddressOfCallBacks;
			tlsInfo = tlsinfo;

		}
		else {

			if (tlsOffset + sizeof(PIMAGE_TLS_DIRECTORY32) > peData.size())  throw PeFormatException("tls truncated");
			IMAGE_TLS_DIRECTORY32 t = read<IMAGE_TLS_DIRECTORY32>(tlsOffset);
			TLSInfo info;
			info.startAddressOfRawData = t.StartAddressOfRawData;
			info.endAddressOfRawData = t.EndAddressOfRawData;
			info.addressOfIndex = t.AddressOfIndex;
			info.addressOfCallbacks = t.AddressOfCallBacks;
			tlsInfo = info;
		}

	}

	// ------------------ Debug directory parsing (basic) ----------------------


	inline void Parser::parseDebugDirectory() {
		// If you want more debug parsing (PDB paths, CodeView) add here.
	// i will just check presence for now

		if (!parsedDirectories) parseDataDirectories();
		auto opt = directoryRvaToOffset(IMAGE_DIRECTORY_ENTRY_DEBUG);
		if (!opt) return;
		size_t debugOffset = *opt;

		// iterate IMAGE_DEBUG_DIRECTORY structures until bounds or zeroed entry
		size_t cur = debugOffset;
		while (cur + sizeof(IMAGE_DEBUG_DIRECTORY) <= peData.size()) {
			IMAGE_DEBUG_DIRECTORY dd = read<IMAGE_DEBUG_DIRECTORY>(cur);
			if (dd.Characteristics == 0 && dd.AddressOfRawData == 0 && dd.SizeOfData == 0 && dd.Type == 0) break;

			// If dd.Type == IMAGE_DEBUG_TYPE_CODEVIEW (2), dd.PointerToRawData points to CV info (PDB path)
			// Add parsing if needed
			cur += sizeof(IMAGE_DEBUG_DIRECTORY);

		}
		// ------------------ Data directories parse (just sanity mapping) ------------
	}
	inline void Parser::parseDataDirectories() {
		if (parsedDirectories) return;
		if (!parsedNt) parseNtHeaders();
		// dataDirectory already copied in parseNtHeaders
		parsedDirectories = true;
	}

	void Parser::parseAll() {

		parseDosHeader();
		parseNtHeaders();
		parseSectionHeaders();
		parseDataDirectories(); // populate dataDirectory pointers
		// parse heavy things on demand or parse everything now:
		parseExports();
		parseImports();
		parseResources();
		parseRelocations();
		parseTLS();
		// debug dir parse optional
		parseDebugDirectory();

	}

	const IMAGE_SECTION_HEADER* Parser::findSectionForRVA(uint32_t rva) const {

		for (const auto& section : sections) {

			uint32_t start = section.VirtualAddress;
			uint32_t size = std::max(section.SizeOfRawData, section.Misc.VirtualSize);
			uint32_t end = start + size;

			if (rva >= start && rva < end) {
				return &section;
			}
		}

		return nullptr;
	}

	std::optional<size_t> Parser::directoryRvaToOffset(DWORD directoryIndex) const {

		if (directoryIndex >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return std::nullopt;

		const auto& data_dir = dataDirectory[directoryIndex];
		if (data_dir.VirtualAddress == 0 || data_dir.Size == 0) return std::nullopt;
		return rvaToOffset(data_dir.VirtualAddress);
	}

	std::string Parser::sectionNameToString(const IMAGE_SECTION_HEADER& sh) {
		
		const char* p = reinterpret_cast<const char*>(sh.Name);

		size_t len = 0;

		while (len < 8 && p[len] != '\0') ++len;

		return std::string(p, len);

	}

	Parser::Parser(const std::vector<uint8_t>& data) : peData(data) {}

}

