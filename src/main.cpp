// main.cpp
// CLI khung cho công cụ ký IPA tự viết. Ở giai đoạn này hỗ trợ:
//   ipa-signer repack <input.ipa> <output.ipa>   -> giải nén rồi nén lại,
//       kiểm chứng pipeline zip hoạt động đúng, CHƯA ký gì cả (Milestone 1)
//   ipa-signer inspect <path/to/binary>          -> in cấu trúc Mach-O
//       của 1 executable/dylib đã giải nén từ .app (Milestone 4)
//
// Việc unzip/zip ở milestone này gọi ra binary hệ thống (unzip/zip) qua
// system() cho đơn giản, tránh phụ thuộc libzip ngay từ đầu. Khi cần ký
// thật (phải stream/patch từng file), nên chuyển sang libzip để kiểm
// soát chính xác từng entry.

#include "macho_parser.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <filesystem>
#include <unistd.h>

namespace fs = std::filesystem;

static int cmdRepack(const std::string& inputIpa, const std::string& outputIpa) {
    fs::path workDir = fs::temp_directory_path() / ("ipa-signer-" + std::to_string(::getpid()));
    fs::create_directories(workDir);

    std::cout << "Giải nén " << inputIpa << " -> " << workDir << "\n";
    std::string unzipCmd = "unzip -q \"" + inputIpa + "\" -d \"" + workDir.string() + "\"";
    if (std::system(unzipCmd.c_str()) != 0) {
        std::cerr << "Giải nén thất bại\n";
        return 1;
    }

    fs::path payloadDir = workDir / "Payload";
    if (!fs::exists(payloadDir)) {
        std::cerr << "IPA không hợp lệ: thiếu thư mục Payload/\n";
        return 1;
    }

    // TODO (milestone sau): ở đây sẽ là chỗ chèn logic ký:
    //  - tìm file .app trong Payload/
    //  - đọc Info.plist lấy tên executable chính
    //  - duyệt framework/plugin con, ký từng Mach-O (macho::parseMachOFile + build SuperBlob)
    //  - ghi lại CodeResources
    //  - thay embedded.mobileprovision

    if (fs::exists(outputIpa)) fs::remove(outputIpa);

    std::cout << "Đóng gói lại -> " << outputIpa << "\n";
    // -X: giữ nguyên metadata, -r: đệ quy. Nén từ bên trong workDir để
    // path trong zip là "Payload/..." chứ không phải đường dẫn tuyệt đối.
    std::string zipCmd = "cd \"" + workDir.string() + "\" && zip -qXr \"" +
                          fs::absolute(outputIpa).string() + "\" Payload";
    if (std::system(zipCmd.c_str()) != 0) {
        std::cerr << "Nén lại thất bại\n";
        return 1;
    }

    fs::remove_all(workDir);
    std::cout << "Xong. (Lưu ý: đây mới chỉ là repack, chưa ký lại chữ ký code sign)\n";
    return 0;
}

static int cmdInspect(const std::string& binaryPath) {
    macho::MachOFile file;
    std::string err;
    if (!macho::parseMachOFile(binaryPath, file, err)) {
        std::cerr << "Lỗi parse: " << err << "\n";
        return 1;
    }
    macho::printMachOInfo(file);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Cách dùng:\n"
                  << "  " << argv[0] << " repack <input.ipa> <output.ipa>\n"
                  << "  " << argv[0] << " inspect <path/to/macho-binary>\n";
        return 1;
    }

    std::string command = argv[1];

    if (command == "repack") {
        if (argc != 4) {
            std::cerr << "Cần đủ tham số: repack <input.ipa> <output.ipa>\n";
            return 1;
        }
        return cmdRepack(argv[2], argv[3]);
    }

    if (command == "inspect") {
        if (argc != 3) {
            std::cerr << "Cần tham số: inspect <path/to/macho-binary>\n";
            return 1;
        }
        return cmdInspect(argv[2]);
    }

    std::cerr << "Lệnh không hợp lệ: " << command << "\n";
    return 1;
}
