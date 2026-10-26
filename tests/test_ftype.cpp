#include "ftype/ftype.hpp"

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

int g_passed = 0;
int g_failed = 0;

void expect_eq(const char* actual, const char* expected, const char* label, int line) {
    if (std::strcmp(actual, expected) == 0) {
        ++g_passed;
    } else {
        ++g_failed;
        std::cerr << "[FAIL] line " << line << " (" << label << "): expected '"
                  << expected << "', got '" << actual << "'\n";
    }
}

#define EXPECT_EXT(ft, exp_ext, label) expect_eq((ft).ext, (exp_ext), (label), __LINE__)

void test_memory_signatures() {
    auto check = [](const void* data, size_t len, const char* exp, const char* label) {
        EXPECT_EXT(ftype::detect_bytes(static_cast<const uint8_t*>(data), len), exp, label);
    };

    check(nullptr, 0, "empty", "null buffer");
    check("\x89PNG\r\n\x1a\n", 8, "png", "png magic");
    check("\xFF\xD8\xFF\xE0", 4, "jpg", "jpg magic");
    check("GIF89a", 6, "gif", "gif89a magic");
    check("RIFF\x00\x00\x00\x00WEBP", 12, "webp", "webp magic");
    check("%PDF-1.7", 8, "pdf", "pdf magic");
    check("\x7F" "ELF", 4, "elf", "elf magic");
    check("MZ\x90\x00", 4, "exe", "pe exe magic");
    check("\x00" "asm", 4, "wasm", "wasm magic");
    check("SQLite format 3\x00", 16, "sqlite", "sqlite3 magic");

    // UTF-8 截断容错测试：4096 字节末尾恰好只剩半个 3 字节汉字（\xE4\xB8）
    std::vector<uint8_t> truncated_utf8(4094, 'a');
    truncated_utf8.push_back(0xE4);
    truncated_utf8.push_back(0xB8);
    EXPECT_EXT(ftype::detect_bytes(truncated_utf8.data(), truncated_utf8.size()), "txt", "truncated utf8 boundary");

    // 非法二进制流
    const uint8_t bad_bin[] = {0x80, 0x81, 0xFE, 0x00, 0x11};
    EXPECT_EXT(ftype::detect_bytes(bad_bin, sizeof(bad_bin)), "unknown", "random binary");
}

void test_text_and_languages() {
    auto check_str = [](const char* s, const char* exp, const char* label) {
        EXPECT_EXT(ftype::detect_bytes(reinterpret_cast<const uint8_t*>(s), std::strlen(s)), exp, label);
    };

    check_str("Hello, 无 BOM 中文 UTF-8!\n", "txt", "plain utf8");
    check_str("\xEF\xBB\xBFWith UTF-8 BOM", "txt", "utf8 with bom");
    check_str("  {\n  \"key\": \"val\"\n}", "json", "json object");
    check_str("[\n  {\"id\": 1}\n]", "json", "json array");
    check_str("<!DOCTYPE html><html></html>", "html", "html doctype");
    check_str("<?xml version=\"1.0\"?><root/>", "xml", "xml header");
    check_str("<svg xmlns=\"http://www.w3.org/2000/svg\"/>", "svg", "svg tag");
    check_str("#!/usr/bin/env bash\necho 1", "sh", "bash shebang");
    check_str("#!/usr/bin/env python3\nprint(1)", "py", "python shebang");
    check_str("#!/usr/bin/env node\nconsole.log(1)", "js", "node shebang");
}

void test_sample_files(const std::string& dir) {
    struct Case {
        const char* file;
        const char* ext;
    };
    const Case cases[] = {
        // 伪装文件
        {"disguised_docx_as.pdf", "docx"},
        {"disguised_png_as.txt", "png"},
        // 图像 (传统 + 现代/专业格式)
        {"sample.png", "png"},
        {"sample.jpg", "jpg"},
        {"sample.gif", "gif"},
        {"sample.webp", "webp"},
        {"sample.bmp", "bmp"},
        {"sample.tif", "tif"},
        {"sample.ico", "ico"},
        {"sample.svg", "svg"},
        {"sample.heic", "heic"},
        {"sample.avif", "avif"},
        {"sample.psd", "psd"},
        {"sample.jxl", "jxl"},
        {"sample.exr", "exr"},
        {"sample.hdr", "hdr"},
        {"sample.dds", "dds"},
        // Office 与文档 (OOXML + ODF + 旧版二进制 OLE2 + 国产 OFD/UOF/WPS/永中 + PDF/RTF/EPUB)
        {"sample.pdf", "pdf"},
        {"sample.ofd", "ofd"},
        {"sample.uof", "uof"},
        {"sample.eio", "eio"},
        {"sample.wps", "wps"},
        {"sample.et", "et"},
        {"sample.dps", "dps"},
        {"sample.rtf", "rtf"},
        {"sample.docx", "docx"},
        {"sample.xlsx", "xlsx"},
        {"sample.pptx", "pptx"},
        {"sample.doc", "doc"},
        {"sample.xls", "xls"},
        {"sample.ppt", "ppt"},
        {"sample.odt", "odt"},
        {"sample.odp", "odp"},
        {"sample.epub", "epub"},
        {"sample.msi", "msi"},
        // 压缩包与系统软件包
        {"sample.zip", "zip"},
        {"sample.rar", "rar"},
        {"sample.7z", "7z"},
        {"sample.gz", "gz"},
        {"sample.bz2", "bz2"},
        {"sample.xz", "xz"},
        {"sample.zst", "zst"},
        {"sample.lz4", "lz4"},
        {"sample.tar", "tar"},
        {"sample.cab", "cab"},
        {"sample.deb", "deb"},
        {"sample.rpm", "rpm"},
        {"sample.apk", "apk"},
        {"sample.jar", "jar"},
        {"sample.ipa", "ipa"},
        // 光盘与虚拟机磁盘镜像
        {"sample.iso", "iso"},
        {"sample.dmg", "dmg"},
        {"sample.qcow2", "qcow2"},
        {"sample.vmdk", "vmdk"},
        {"sample.vhd", "vhd"},
        // 字体
        {"sample.ttf", "ttf"},
        {"sample.otf", "otf"},
        {"sample.woff", "woff"},
        {"sample.woff2", "woff2"},
        // 可执行文件、数据库与抓包
        {"sample.elf", "elf"},
        {"sample.exe", "exe"},
        {"sample.macho", "macho"},
        {"sample.class", "class"},
        {"sample.wasm", "wasm"},
        {"sample.sqlite", "sqlite"},
        {"sample.pcap", "pcap"},
        // 音视频
        {"sample.wav", "wav"},
        {"sample.avi", "avi"},
        {"sample.mp3", "mp3"},
        {"sample.flac", "flac"},
        {"sample.ogg", "ogg"},
        {"sample.mkv", "mkv"},
        {"sample.webm", "webm"},
        {"sample.mp4", "mp4"},
        {"sample.mov", "mov"},
        {"sample.m4a", "m4a"},
        {"sample.flv", "flv"},
        {"sample.mid", "mid"},
        // 编程语言与数据配置
        {"sample.c", "c"},
        {"sample.cpp", "cpp"},
        {"sample.py", "py"},
        {"sample.rs", "rs"},
        {"sample.go", "go"},
        {"sample.java", "java"},
        {"sample.js", "js"},
        {"sample.ts", "ts"},
        {"sample.php", "php"},
        {"sample.sh", "sh"},
        {"sample.sql", "sql"},
        {"sample.json", "json"},
        {"sample.xml", "xml"},
        {"sample.html", "html"},
        {"sample.css", "css"},
        {"sample.yaml", "yaml"},
        {"sample.md", "md"},
        {"sample.ini", "ini"},
        {"sample.txt", "txt"},
        {"sample_utf16.txt", "txt"},
        {"sample_unknown.bin", "unknown"},
    };

    for (const auto& c : cases) {
        std::string path = dir + "/" + c.file;
        EXPECT_EXT(ftype::detect_file(path), c.ext, c.file);
    }
    EXPECT_EXT(ftype::detect_file(dir + "/non_existent_file.xyz"), "error", "missing file");
}

} // namespace

int main(int argc, char** argv) {
    std::string sample_dir = (argc > 1) ? argv[1] : "test_samples";

    test_memory_signatures();
    test_text_and_languages();
    test_sample_files(sample_dir);

    std::cout << "[Unit Tests] Passed: " << g_passed << ", Failed: " << g_failed << "\n";
    return g_failed == 0 ? 0 : 1;
}
