# ipa-signer (C++) — khung xây dựng công cụ ký IPA tự viết

Mục tiêu: hiểu và tự cài đặt lại quy trình mà zsign làm, thay vì gọi nó
như hộp đen. Code hiện tại đã build & test được (đã compile-check trong
môi trường này), nhưng **chưa ký được gì cả** — mới dừng ở bước nền tảng.

## Đã có (build được ngay, không cần thư viện ngoài)

- `include/macho_defs.h` — struct/constant của định dạng Mach-O (header,
  load command, fat binary, SuperBlob chữ ký) viết lại thủ công theo
  đúng chuẩn Apple công bố công khai (mach-o/loader.h, cs_blobs.h).
- `include/macho_parser.h`, `src/macho_parser.cpp` — đọc 1 file Mach-O
  (hỗ trợ cả fat/universal binary), duyệt toàn bộ load command, tìm
  `LC_CODE_SIGNATURE` cũ và segment `__LINKEDIT`.
- `src/main.cpp` — CLI với 2 lệnh:
  - `repack <in.ipa> <out.ipa>`: giải nén rồi nén lại IPA, xác nhận
    pipeline zip đúng (chưa đổi/ký gì bên trong).
  - `inspect <file>`: in cấu trúc Mach-O của 1 binary, dùng để debug khi
    xây các milestone tiếp theo — thử với file executable chính lấy từ
    trong `YourApp.app/` sau khi giải nén 1 IPA thật.

## Build

```bash
make
./ipa-signer repack MyApp.ipa MyApp-repacked.ipa
./ipa-signer inspect /path/to/extracted/Payload/MyApp.app/MyApp
```

Yêu cầu máy build: `g++` hỗ trợ C++17, lệnh `unzip`/`zip` có sẵn trong
PATH (milestone 1 gọi qua `system()`).

## Lộ trình tiếp theo (theo đúng thứ tự phụ thuộc)

1. ~~Repack IPA~~ ✅ (đã có)
2. ~~Đọc cấu trúc Mach-O, tìm LC_CODE_SIGNATURE / __LINKEDIT~~ ✅ (đã có)
3. **Đọc Info.plist**: cần xử lý cả plist dạng XML lẫn binary plist
   (bplist00) — app thật hầu hết dùng bplist. Có thể viết parser bplist
   riêng (không quá phức tạp, định dạng có tài liệu công khai), hoặc
   dùng thư viện `libplist` (từ dự án libimobiledevice) để đỡ tốn công.
4. **Đọc .mobileprovision**: về bản chất là 1 khối CMS/PKCS7 chứa 1
   plist bên trong. Dùng OpenSSL (`PKCS7_*` API hoặc `CMS_*` API) để
   verify + trích xuất phần plist chứa entitlements.
5. **Tạo CodeResources**: duyệt toàn bộ file trong `.app` (trừ vài file
   loại trừ theo rule của Apple: `_CodeSignature/`, `CodeResources`
   chính nó, v.v.), băm SHA-1 và SHA-256 từng file, ghi ra plist theo
   đúng cấu trúc `files`/`files2` mà Apple dùng.
6. **Build CodeDirectory**: dùng lại `MachOArch` đã parse ở bước 2 — với
   mỗi binary, chia `codeLimit` byte đầu (trước LC_CODE_SIGNATURE) thành
   các trang 4096 byte, băm SHA-256 từng trang, điền vào struct
   `CS_CodeDirectory` đã định nghĩa sẵn trong `macho_defs.h`.
7. **Ký CMS**: dùng OpenSSL (`CMS_sign` với flag `CMS_BINARY | CMS_NOSMIMECAP`,
   detached) ký lên CodeDirectory (đã hash), dùng private key + cert
   chain load từ `.p12` (`PKCS12_parse`).
8. **Ghép SuperBlob và ghi đè vào binary**: gộp CodeDirectory +
   Requirements + Entitlements + BlobWrapper (CMS) theo đúng offset
   trong `CS_SuperBlob`/`CS_BlobIndex`, ghi vào đúng `dataoff` của
   `LC_CODE_SIGNATURE` (thêm mới load command này nếu binary chưa có,
   phức tạp hơn vì phải dịch chuyển `__LINKEDIT`).
9. Lặp lại bước 6–8 cho mọi framework/dylib/appex con **trước khi** ký
   executable chính (vì entitlements/requirements của app cha có thể
   tham chiếu tới chữ ký của thành phần con).
10. Thay `embedded.mobileprovision`, đóng gói lại `.ipa`.

Ở mỗi bước, nên đối chiếu kết quả với `zsign` (chạy trên máy có sẵn nó)
hoặc lệnh `codesign -dvvv --verify` (nếu có Mac ảo qua CI) để biết mình
làm đúng hay sai — signing sai dù 1 byte cũng khiến iOS từ chối chạy app.

## Dependencies cần cài trên máy build thật của bạn (không có ở đây)

```bash
sudo apt install libssl-dev libzip-dev cmake  # Ubuntu/Debian
```

`libssl-dev` cho bước 4 và 7 (PKCS7/CMS). `libzip-dev` để thay `system()`
gọi unzip/zip bằng thao tác zip trực tiếp trong code (cần thiết khi
milestone sau phải sửa file bên trong .ipa theo stream thay vì
giải nén toàn bộ ra đĩa).
