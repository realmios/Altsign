// macho_defs.h
// Định nghĩa lại các struct/constant của định dạng Mach-O.
// Tham chiếu từ mach-o/loader.h và mach-o/fat.h của Apple (mã nguồn mở
// trong XNU / cctools). Viết lại thủ công vì ta build trên Linux, không
// có sẵn header hệ thống của Apple.

#pragma once
#include <cstdint>

namespace macho {

// ---- Magic numbers ----
constexpr uint32_t MH_MAGIC     = 0xfeedface; // Mach-O 32-bit, cùng endian
constexpr uint32_t MH_CIGAM     = 0xcefaedfe; // Mach-O 32-bit, khác endian
constexpr uint32_t MH_MAGIC_64  = 0xfeedfacf; // Mach-O 64-bit, cùng endian
constexpr uint32_t MH_CIGAM_64  = 0xfcfaedfe; // Mach-O 64-bit, khác endian
constexpr uint32_t FAT_MAGIC    = 0xcafebabe; // Fat/universal binary
constexpr uint32_t FAT_CIGAM    = 0xbebafeca;

// ---- Load command types (chỉ liệt kê cái cần cho việc ký) ----
constexpr uint32_t LC_SEGMENT           = 0x01;
constexpr uint32_t LC_SEGMENT_64        = 0x19;
constexpr uint32_t LC_CODE_SIGNATURE    = 0x1d;
constexpr uint32_t LC_SYMTAB            = 0x02;
constexpr uint32_t LC_DYLIB_CODE_SIGN_DRS = 0x1e;

// ---- Header 64-bit ----
#pragma pack(push, 1)
struct mach_header_64 {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;      // số lượng load command
    uint32_t sizeofcmds; // tổng kích thước vùng load command
    uint32_t flags;
    uint32_t reserved;
};

struct mach_header {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

// LC_CODE_SIGNATURE trỏ tới vùng chữ ký nằm cuối file (thường trong __LINKEDIT)
struct linkedit_data_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;  // offset (từ đầu file) tới vùng dữ liệu
    uint32_t datasize; // kích thước vùng dữ liệu (SuperBlob chữ ký)
};

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
};

// ---- Fat / universal binary header ----
struct fat_header {
    uint32_t magic;
    uint32_t nfat_arch; // số kiến trúc (arm64, armv7, ...) chứa trong file
};

struct fat_arch {
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t offset; // offset tới phần Mach-O của kiến trúc này
    uint32_t size;
    uint32_t align;
};
#pragma pack(pop)

// ---- Code signature SuperBlob (định dạng vùng ký, theo cs_blobs.h) ----
constexpr uint32_t CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
constexpr uint32_t CSMAGIC_CODEDIRECTORY      = 0xfade0c02;
constexpr uint32_t CSMAGIC_REQUIREMENTS       = 0xfade0c01;
constexpr uint32_t CSMAGIC_ENTITLEMENTS       = 0xfade7171;
constexpr uint32_t CSMAGIC_BLOBWRAPPER        = 0xfade0b01; // chứa CMS signature

constexpr uint32_t CSSLOT_CODEDIRECTORY = 0;
constexpr uint32_t CSSLOT_REQUIREMENTS  = 2;
constexpr uint32_t CSSLOT_ENTITLEMENTS  = 5;
constexpr uint32_t CSSLOT_SIGNATURESLOT = 0x10001;

#pragma pack(push, 1)
struct CS_SuperBlob {
    uint32_t magic;  // CSMAGIC_EMBEDDED_SIGNATURE
    uint32_t length; // tổng kích thước SuperBlob
    uint32_t count;  // số blob con
    // theo sau là `count` phần tử CS_BlobIndex
};

struct CS_BlobIndex {
    uint32_t type;   // CSSLOT_*
    uint32_t offset; // offset (từ đầu SuperBlob) tới blob này
};

struct CS_CodeDirectory {
    uint32_t magic;         // CSMAGIC_CODEDIRECTORY
    uint32_t length;
    uint32_t version;       // vd 0x20400
    uint32_t flags;
    uint32_t hashOffset;    // offset tới mảng hash (tính từ đầu CodeDirectory)
    uint32_t identOffset;   // offset tới chuỗi identifier (thường = bundle id)
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;    // số page đã băm
    uint32_t codeLimit;     // kích thước phần dữ liệu được ký (trước LC_CODE_SIGNATURE)
    uint8_t  hashSize;      // 20 (SHA-1) hoặc 32 (SHA-256)
    uint8_t  hashType;      // 1 = SHA-1, 2 = SHA-256
    uint8_t  platform;
    uint8_t  pageSize;      // log2(page size), thường = 12 (4096 byte)
    uint32_t spare2;
    // các field mới hơn (teamOffset, ...) tuỳ version, thêm sau khi cần
};
#pragma pack(pop)

} // namespace macho
