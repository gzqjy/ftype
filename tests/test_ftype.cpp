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

    std::vector<uint8_t> truncated_utf8(4094, 'a');
    truncated_utf8.push_back(0xE4);
    truncated_utf8.push_back(0xB8);
    EXPECT_EXT(ftype::detect_bytes(truncated_utf8.data(), truncated_utf8.size()), "txt", "truncated utf8 boundary");

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
        // 1. 文本文档、办公、国产文献、电子书与帮助文件
        {"sample.pdf", "pdf"},
        {"sample.ofd", "ofd"},
        {"sample.uof", "uof"},
        {"sample.eio", "eio"},
        {"sample.wps", "wps"},
        {"sample.wpt", "wpt"},
        {"sample.et", "et"},
        {"sample.dps", "dps"},
        {"sample.caj", "caj"},
        {"sample.kdh", "kdh"},
        {"sample.ceb", "ceb"},
        {"sample.cebx", "cebx"},
        {"sample.mobi", "mobi"},
        {"sample.azw", "azw"},
        {"sample.azw3", "azw3"},
        {"sample.fb2", "fb2"},
        {"sample.djvu", "djvu"},
        {"sample.indd", "indd"},
        {"sample.ps", "ps"},
        {"sample.eps", "eps"},
        {"sample.rtf", "rtf"},
        {"sample.chm", "chm"},
        {"sample.hlp", "hlp"},
        {"sample.docx", "docx"},
        {"sample.docm", "docm"},
        {"sample.dotx", "dotx"},
        {"sample.xlsx", "xlsx"},
        {"sample.xlsm", "xlsm"},
        {"sample.xltx", "xltx"},
        {"sample.xlsb", "xlsb"},
        {"sample.pptx", "pptx"},
        {"sample.pptm", "pptm"},
        {"sample.ppsx", "ppsx"},
        {"sample.potx", "potx"},
        {"sample.doc", "doc"},
        {"sample.xls", "xls"},
        {"sample.ppt", "ppt"},
        {"sample.odt", "odt"},
        {"sample.ott", "ott"},
        {"sample.ods", "ods"},
        {"sample.ots", "ots"},
        {"sample.odp", "odp"},
        {"sample.otp", "otp"},
        {"sample.epub", "epub"},
        {"sample.csv", "csv"},
        {"sample.tsv", "tsv"},
        {"sample.msi", "msi"},
        // 2. 图像、相机 RAW、CAD 与 3D 模型
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
        {"sample.psb", "psb"},
        {"sample.ai", "ai"},
        {"sample.jxl", "jxl"},
        {"sample.exr", "exr"},
        {"sample.hdr", "hdr"},
        {"sample.dds", "dds"},
        {"sample.dng", "dng"},
        {"sample.nef", "nef"},
        {"sample.arw", "arw"},
        {"sample.cr2", "cr2"},
        {"sample.cr3", "cr3"},
        {"sample.orf", "orf"},
        {"sample.rw2", "rw2"},
        {"sample.raf", "raf"},
        {"sample.dwg", "dwg"},
        {"sample.dxf", "dxf"},
        {"sample.glb", "glb"},
        {"sample.gltf", "gltf"},
        {"sample.blend", "blend"},
        {"sample.fbx", "fbx"},
        {"sample.stl", "stl"},
        {"sample.obj", "obj"},
        {"sample.3ds", "3ds"},
        {"sample.shp", "shp"},
        {"sample.fits", "fits"},
        // 3 & 4. 音频、视频与字幕
        {"sample.wav", "wav"},
        {"sample.aiff", "aiff"},
        {"sample.avi", "avi"},
        {"sample.mp3", "mp3"},
        {"sample.aac", "aac"},
        {"sample.amr", "amr"},
        {"sample.ape", "ape"},
        {"sample.wv", "wv"},
        {"sample.dsf", "dsf"},
        {"sample.dff", "dff"},
        {"sample.flac", "flac"},
        {"sample.ogg", "ogg"},
        {"sample.opus", "opus"},
        {"sample.ogv", "ogv"},
        {"sample.wma", "wma"},
        {"sample.wmv", "wmv"},
        {"sample.mkv", "mkv"},
        {"sample.webm", "webm"},
        {"sample.mp4", "mp4"},
        {"sample.m4v", "m4v"},
        {"sample.mov", "mov"},
        {"sample.m4a", "m4a"},
        {"sample.3g2", "3g2"},
        {"sample.mpg", "mpg"},
        {"sample.vob", "vob"},
        {"sample_video.ts", "ts"},
        {"sample.m2ts", "m2ts"},
        {"sample.mxf", "mxf"},
        {"sample.flv", "flv"},
        {"sample.mid", "mid"},
        {"sample.srt", "srt"},
        {"sample.vtt", "vtt"},
        // 5. 压缩包、归档、软件包与扩展
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
        {"sample.wim", "wim"},
        {"sample.xar", "xar"},
        {"sample.crx", "crx"},
        {"sample.xpi", "xpi"},
        {"sample.deb", "deb"},
        {"sample.rpm", "rpm"},
        {"sample.apk", "apk"},
        {"sample.aab", "aab"},
        {"sample.jar", "jar"},
        {"sample.war", "war"},
        {"sample.ear", "ear"},
        {"sample.ipa", "ipa"},
        {"sample.msix", "msix"},
        // 6. 编程语言与源代码文件
        {"sample.c", "c"},
        {"sample.cpp", "cpp"},
        {"sample.cs", "cs"},
        {"sample.java", "java"},
        {"sample.kt", "kt"},
        {"sample.rs", "rs"},
        {"sample.go", "go"},
        {"sample.py", "py"},
        {"sample.pyc", "pyc"},
        {"sample.js", "js"},
        {"sample.ts", "ts"},
        {"sample.tsx", "tsx"},
        {"sample.html", "html"},
        {"sample.css", "css"},
        {"sample.scss", "scss"},
        {"sample.php", "php"},
        {"sample.rb", "rb"},
        {"sample.swift", "swift"},
        {"sample.m", "m"},
        {"sample.lua", "lua"},
        {"sample.sh", "sh"},
        {"sample.ps1", "ps1"},
        {"sample.bat", "bat"},
        {"sample.asm", "asm"},
        {"sample.wasm", "wasm"},
        {"sample.wat", "wat"},
        {"sample.sql", "sql"},
        {"sample.proto", "proto"},
        {"sample.ui", "ui"},
        {"sample.qrc", "qrc"},
        {"sample.qml", "qml"},
        {"sample.cu", "cu"},
        // 7. 配置、数据交换与科学数据
        {"sample.json", "json"},
        {"sample.jsonl", "jsonl"},
        {"sample.bson", "bson"},
        {"sample.xml", "xml"},
        {"sample.yaml", "yaml"},
        {"sample.toml", "toml"},
        {"sample.ini", "ini"},
        {"sample.properties", "properties"},
        {"sample.env", "env"},
        {"sample.http", "http"},
        {"sample.har", "har"},
        {"sample.rss", "rss"},
        {"sample.atom", "atom"},
        {"sample.webmanifest", "webmanifest"},
        {"sample.graphql", "graphql"},
        {"sample.parquet", "parquet"},
        {"sample.orc", "orc"},
        {"sample.avro", "avro"},
        {"sample.arrow", "arrow"},
        {"sample.feather", "feather"},
        {"sample.h5", "h5"},
        {"sample.nc", "nc"},
        {"sample.npy", "npy"},
        {"sample.npz", "npz"},
        {"sample.gguf", "gguf"},
        // 8. 数据库与搜索索引
        {"sample.sqlite", "sqlite"},
        {"sample.mdf", "mdf"},
        {"sample.mdb", "mdb"},
        {"sample.accdb", "accdb"},
        {"sample.dbf", "dbf"},
        {"sample.db", "db"},
        {"sample.lmdb", "lmdb"},
        {"sample.sst", "sst"},
        {"sample.rdb", "rdb"},
        {"sample.cfs", "cfs"},
        {"sample.pst", "pst"},
        {"sample.kdbx", "kdbx"},
        // 9. 可执行文件、库、目标文件与调试符号
        {"sample.elf", "elf"},
        {"sample.so", "so"},
        {"sample.o", "o"},
        {"sample.ko", "ko"},
        {"sample.core", "core"},
        {"sample.appimage", "appimage"},
        {"sample.exe", "exe"},
        {"sample.dll", "dll"},
        {"sample.sys", "sys"},
        {"sample.coff", "coff"},
        {"sample.pdb", "pdb"},
        {"sample.macho", "macho"},
        {"sample.class", "class"},
        {"sample.hex", "hex"},
        // 10. 磁盘镜像与虚拟机
        {"sample.iso", "iso"},
        {"sample.dmg", "dmg"},
        {"sample.qcow2", "qcow2"},
        {"sample.vmdk", "vmdk"},
        {"sample.vhd", "vhd"},
        {"sample.vhdx", "vhdx"},
        {"sample.vmx", "vmx"},
        {"sample.vbox", "vbox"},
        {"sample.ovf", "ovf"},
        {"sample.ova", "ova"},
        {"sample.dmp", "dmp"},
        {"sample.swp", "swp"},
        {"sample.swap", "swap"},
        // 11 & 12. 证书、字体、邮件、日历与系统文件
        {"sample.pem", "pem"},
        {"sample.der", "der"},
        {"sample.p7b", "p7b"},
        {"sample.p8", "p8"},
        {"sample.p12", "p12"},
        {"sample.key", "key"},
        {"sample.asc", "asc"},
        {"sample.gpg", "gpg"},
        {"sample.pub", "pub"},
        {"sample.ttf", "ttf"},
        {"sample.otf", "otf"},
        {"sample.woff", "woff"},
        {"sample.woff2", "woff2"},
        {"sample.fon", "fon"},
        {"sample.eml", "eml"},
        {"sample.mbox", "mbox"},
        {"sample.ics", "ics"},
        {"sample.vcf", "vcf"},
        {"sample.lnk", "lnk"},
        {"sample.reg", "reg"},
        {"sample.hiv", "hiv"},
        {"sample.evtx", "evtx"},
        {"sample.ab", "ab"},
        {"sample.plist", "plist"},
        {"sample.pcap", "pcap"},
        {"sample.md", "md"},
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
