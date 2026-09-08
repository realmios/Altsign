// macho_parser.h
#pragma once
#include "macho_defs.h"
#include <string>
#include <vector>
#include <optional>

namespace macho {

struct LoadCommandInfo {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t fileOffset; // offset của load command này trong file
};

struct CodeSignatureInfo {
    uint64_t fileOffset;  // offset của linkedit_data_command trong file
    uint32_t dataOffset;  // dataoff: nơi SuperBlob bắt đầu
    uint32_t dataSize;    // datasize: kích thước SuperBlob hiện tại
};

// Kết quả parse 1 kiến trúc (arch) Mach-O cụ thể (sau khi đã bỏ fat header nếu có)
struct MachOArch {
    uint64_t archFileOffset = 0; // offset của arch này trong file gốc (0 nếu thin binary)
    bool is64 = false;
    bool isBigEndian = false;
    int32_t cputype = 0;
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;
    uint64_t headerSize = 0; // kích thước mach_header (32 hoặc 64-bit)

    std::vector<LoadCommandInfo> loadCommands;
    std::optional<CodeSignatureInfo> codeSignature; // LC_CODE_SIGNATURE nếu có
    std::optional<uint64_t> linkeditFileOffset;      // fileoff của segment __LINKEDIT
    std::optional<uint64_t> linkeditFileSize;        // filesize của segment __LINKEDIT
};

struct MachOFile {
    bool isFat = false;
    std::vector<MachOArch> archs; // 1 phần tử nếu thin, nhiều nếu fat/universal
};

// Đọc và parse toàn bộ file Mach-O (hoặc fat binary chứa nhiều Mach-O).
// Trả về false nếu không phải định dạng hợp lệ.
bool parseMachOFile(const std::string& path, MachOFile& out, std::string& errorMsg);

// In thông tin ra stdout, phục vụ debug/verify khi học lại từng bước
void printMachOInfo(const MachOFile& file);

} // namespace macho
