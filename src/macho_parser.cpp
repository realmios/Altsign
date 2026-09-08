// macho_parser.cpp
#include "macho_parser.h"
#include <fstream>
#include <cstring>
#include <iostream>

namespace macho {

namespace {

uint32_t swap32(uint32_t v) {
    return ((v & 0x000000FF) << 24) |
           ((v & 0x0000FF00) << 8)  |
           ((v & 0x00FF0000) >> 8)  |
           ((v & 0xFF000000) >> 24);
}

// Đọc toàn bộ file vào buffer. Với app thật (vài chục MB) cách này ổn;
// nếu sau này xử lý app lớn, nên chuyển sang mmap để đỡ tốn RAM.
bool readFile(const std::string& path, std::vector<uint8_t>& buf, std::string& err) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { err = "Không mở được file: " + path; return false; }
    std::streamsize size = f.tellg();
    if (size <= 0) { err = "File rỗng hoặc lỗi: " + path; return false; }
    f.seekg(0, std::ios::beg);
    buf.resize(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(buf.data()), size)) {
        err = "Đọc file thất bại: " + path;
        return false;
    }
    return true;
}

// Parse 1 Mach-O "thin" bắt đầu tại offset `base` trong buffer toàn cục.
bool parseThinArch(const std::vector<uint8_t>& buf, uint64_t base, MachOArch& arch, std::string& err) {
    if (base + 4 > buf.size()) { err = "Offset vượt quá kích thước file"; return false; }

    uint32_t magic;
    std::memcpy(&magic, buf.data() + base, 4);

    bool is64 = false;
    bool bigEndian = false;

    if (magic == MH_MAGIC_64) { is64 = true;  bigEndian = false; }
    else if (magic == MH_CIGAM_64) { is64 = true;  bigEndian = true; }
    else if (magic == MH_MAGIC) { is64 = false; bigEndian = false; }
    else if (magic == MH_CIGAM) { is64 = false; bigEndian = true; }
    else { err = "Không phải Mach-O hợp lệ (magic sai)"; return false; }

    arch.archFileOffset = base;
    arch.is64 = is64;
    arch.isBigEndian = bigEndian;

    uint32_t ncmds, sizeofcmds;
    int32_t cputype;
    uint64_t headerSize;

    if (is64) {
        mach_header_64 hdr;
        if (base + sizeof(hdr) > buf.size()) { err = "File cắt cụt ở mach_header_64"; return false; }
        std::memcpy(&hdr, buf.data() + base, sizeof(hdr));
        if (bigEndian) {
            hdr.ncmds = swap32(hdr.ncmds);
            hdr.sizeofcmds = swap32(hdr.sizeofcmds);
            hdr.cputype = static_cast<int32_t>(swap32(static_cast<uint32_t>(hdr.cputype)));
        }
        ncmds = hdr.ncmds;
        sizeofcmds = hdr.sizeofcmds;
        cputype = hdr.cputype;
        headerSize = sizeof(mach_header_64);
    } else {
        mach_header hdr;
        if (base + sizeof(hdr) > buf.size()) { err = "File cắt cụt ở mach_header"; return false; }
        std::memcpy(&hdr, buf.data() + base, sizeof(hdr));
        if (bigEndian) {
            hdr.ncmds = swap32(hdr.ncmds);
            hdr.sizeofcmds = swap32(hdr.sizeofcmds);
            hdr.cputype = static_cast<int32_t>(swap32(static_cast<uint32_t>(hdr.cputype)));
        }
        ncmds = hdr.ncmds;
        sizeofcmds = hdr.sizeofcmds;
        cputype = hdr.cputype;
        headerSize = sizeof(mach_header);
    }

    arch.ncmds = ncmds;
    arch.sizeofcmds = sizeofcmds;
    arch.cputype = cputype;
    arch.headerSize = headerSize;

    uint64_t cursor = base + headerSize;
    for (uint32_t i = 0; i < ncmds; ++i) {
        if (cursor + sizeof(load_command) > buf.size()) {
            err = "File cắt cụt khi đọc load command #" + std::to_string(i);
            return false;
        }
        load_command lc;
        std::memcpy(&lc, buf.data() + cursor, sizeof(lc));
        if (bigEndian) {
            lc.cmd = swap32(lc.cmd);
            lc.cmdsize = swap32(lc.cmdsize);
        }
        if (lc.cmdsize == 0 || cursor + lc.cmdsize > buf.size()) {
            err = "cmdsize không hợp lệ ở load command #" + std::to_string(i);
            return false;
        }

        arch.loadCommands.push_back({lc.cmd, lc.cmdsize, cursor});

        if (lc.cmd == LC_CODE_SIGNATURE) {
            linkedit_data_command ldc;
            std::memcpy(&ldc, buf.data() + cursor, sizeof(ldc));
            if (bigEndian) {
                ldc.dataoff = swap32(ldc.dataoff);
                ldc.datasize = swap32(ldc.datasize);
            }
            CodeSignatureInfo info;
            info.fileOffset = cursor;
            info.dataOffset = ldc.dataoff;
            info.dataSize = ldc.datasize;
            arch.codeSignature = info;
        } else if (is64 && lc.cmd == LC_SEGMENT_64) {
            segment_command_64 seg;
            std::memcpy(&seg, buf.data() + cursor, sizeof(seg));
            // segname không null-terminate đảm bảo, so sánh an toàn bằng strncmp
            if (std::strncmp(seg.segname, "__LINKEDIT", 16) == 0) {
                arch.linkeditFileOffset = seg.fileoff;
                arch.linkeditFileSize = seg.filesize;
            }
        }

        cursor += lc.cmdsize;
    }

    return true;
}

} // namespace

bool parseMachOFile(const std::string& path, MachOFile& out, std::string& errorMsg) {
    std::vector<uint8_t> buf;
    if (!readFile(path, buf, errorMsg)) return false;
    if (buf.size() < 4) { errorMsg = "File quá nhỏ để là Mach-O"; return false; }

    uint32_t magic;
    std::memcpy(&magic, buf.data(), 4);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        bool bigEndian = (magic == FAT_CIGAM);
        fat_header fh;
        std::memcpy(&fh, buf.data(), sizeof(fh));
        uint32_t nfat = bigEndian ? swap32(fh.nfat_arch) : fh.nfat_arch;

        out.isFat = true;
        uint64_t cursor = sizeof(fat_header);
        for (uint32_t i = 0; i < nfat; ++i) {
            if (cursor + sizeof(fat_arch) > buf.size()) {
                errorMsg = "Fat header cắt cụt ở arch #" + std::to_string(i);
                return false;
            }
            fat_arch fa;
            std::memcpy(&fa, buf.data() + cursor, sizeof(fa));
            uint32_t offset = bigEndian ? swap32(fa.offset) : fa.offset;

            MachOArch arch;
            std::string err;
            if (!parseThinArch(buf, offset, arch, err)) {
                errorMsg = "Lỗi parse arch #" + std::to_string(i) + ": " + err;
                return false;
            }
            out.archs.push_back(std::move(arch));
            cursor += sizeof(fat_arch);
        }
        return true;
    }

    // Không phải fat -> thử parse như thin Mach-O
    out.isFat = false;
    MachOArch arch;
    if (!parseThinArch(buf, 0, arch, errorMsg)) return false;
    out.archs.push_back(std::move(arch));
    return true;
}

void printMachOInfo(const MachOFile& file) {
    std::cout << (file.isFat ? "Fat/universal binary" : "Thin Mach-O binary")
              << ", " << file.archs.size() << " kiến trúc\n";

    for (size_t i = 0; i < file.archs.size(); ++i) {
        const auto& arch = file.archs[i];
        std::cout << "  [" << i << "] cputype=" << arch.cputype
                  << (arch.is64 ? " (64-bit)" : " (32-bit)")
                  << ", ncmds=" << arch.ncmds
                  << ", offset trong file=" << arch.archFileOffset << "\n";

        if (arch.linkeditFileOffset) {
            std::cout << "      __LINKEDIT: fileoff=" << *arch.linkeditFileOffset
                      << " filesize=" << *arch.linkeditFileSize << "\n";
        }

        if (arch.codeSignature) {
            std::cout << "      LC_CODE_SIGNATURE: dataoff=" << arch.codeSignature->dataOffset
                      << " datasize=" << arch.codeSignature->dataSize
                      << " (đã có chữ ký cũ, cần thay thế khi ký lại)\n";
        } else {
            std::cout << "      Chưa có LC_CODE_SIGNATURE (cần thêm mới load command này)\n";
        }
    }
}

} // namespace macho
