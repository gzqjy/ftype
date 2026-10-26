#include "ftype/ftype.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <vector>

namespace ftype {
namespace {

bool match(const uint8_t* buf, size_t len, size_t offset, const void* sig, size_t sig_len) {
    return len >= offset + sig_len && std::memcmp(buf + offset, sig, sig_len) == 0;
}

bool match_ci(const uint8_t* buf, size_t len, size_t offset, const char* sig) {
    size_t sig_len = std::strlen(sig);
    if (len < offset + sig_len) return false;
    for (size_t i = 0; i < sig_len; ++i) {
        if (std::tolower(buf[offset + i]) != std::tolower(static_cast<unsigned char>(sig[i]))) return false;
    }
    return true;
}

bool has_str(const uint8_t* buf, size_t len, const char* s) {
    size_t slen = std::strlen(s);
    return len >= slen && std::search(buf, buf + len, s, s + slen) != buf + len;
}

bool has_bytes(const uint8_t* buf, size_t len, const void* pat, size_t pat_len) {
    const uint8_t* p = static_cast<const uint8_t*>(pat);
    return len >= pat_len && std::search(buf, buf + len, p, p + pat_len) != buf + len;
}

// 1. 细分 ZIP 容器 (OFD / UOF / EIO / CEBX / NPZ / XLSB / OOXML / ODF / EPUB / APK / AAB / WAR / EAR / XPI / MSIX / JAR / IPA / VSDX)
FileType classify_zip(const uint8_t* b, size_t n) {
    if (match(b, n, 30, "mimetype", 8)) {
        if (match(b, n, 38, "application/epub+zip", 20)) return {"epub", "application/epub+zip"};
        if (match(b, n, 38, "application/vnd.oasis.opendocument.text", 39)) return {"odt", "application/vnd.oasis.opendocument.text"};
        if (match(b, n, 38, "application/vnd.oasis.opendocument.spreadsheet", 46)) return {"ods", "application/vnd.oasis.opendocument.spreadsheet"};
        if (match(b, n, 38, "application/vnd.oasis.opendocument.presentation", 47)) return {"odp", "application/vnd.oasis.opendocument.presentation"};
    }
    if (has_str(b, n, "OFD.xml")) return {"ofd", "application/ofd"};
    if (has_str(b, n, "Yozo") || has_str(b, n, "yozo") || has_str(b, n, "EIO_")) return {"eio", "application/x-yozo-eio"};
    if (has_str(b, n, "uof.xml") || (has_str(b, n, "content.xml") && has_str(b, n, "uof:"))) return {"uof", "application/vnd.uof"};
    if (has_str(b, n, "cebx") || has_str(b, n, "CEBX")) return {"cebx", "application/vnd.apabi.cebx"};
    if (has_str(b, n, ".npy")) return {"npz", "application/x-numpy-npz"};
    if (has_str(b, n, "BundleConfig.pb")) return {"aab", "application/x-authorware-bin"};
    if (has_str(b, n, "AppxManifest.xml")) return {"msix", "application/msix"};
    if (has_str(b, n, "WEB-INF/")) return {"war", "application/java-archive"};
    if (has_str(b, n, "META-INF/application.xml")) return {"ear", "application/java-archive"};
    if (has_str(b, n, "mozilla.rsa") || has_str(b, n, "install.rdf")) return {"xpi", "application/x-xpinstall"};
    if (has_str(b, n, "xl/workbook.bin")) return {"xlsb", "application/vnd.ms-excel.sheet.binary.macroEnabled.12"};
    if (has_str(b, n, "word/")) return {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"};
    if (has_str(b, n, "xl/")) return {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"};
    if (has_str(b, n, "ppt/")) return {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"};
    if (has_str(b, n, "visio/")) return {"vsdx", "application/vnd.ms-visio.drawing"};
    if (has_str(b, n, "AndroidManifest.xml") || has_str(b, n, "classes.dex")) return {"apk", "application/vnd.android.package-archive"};
    if (has_str(b, n, "Payload/")) return {"ipa", "application/x-ios-app"};
    if (has_str(b, n, "META-INF/")) return {"jar", "application/java-archive"};
    return {"zip", "application/zip"};
}

// 2. 细分 OLE2 复合文档 (WPS 专用 wps/et/dps、永中 eio 及 MS Office doc/xls/ppt/vsd/msg/msi)
FileType classify_ole2(const uint8_t* b, size_t n) {
    static const uint8_t kWpsDoc[] = {'W',0,'P',0,'S',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
    static const uint8_t kWpsEt[]  = {'E',0,'T',0,'W',0,'o',0,'r',0,'k',0,'b',0,'o',0,'o',0,'k',0};
    static const uint8_t kWpsDps[] = {'D',0,'P',0,'S',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
    static const uint8_t kKso[]    = {'K',0,'S',0,'O',0,'P',0,'r',0,'o',0,'d',0,'u',0,'c',0,'t',0};
    static const uint8_t kYozo1[]  = {'Y',0,'o',0,'z',0,'o',0};
    static const uint8_t kYozo2[]  = {'E',0,'I',0,'O',0,'_',0};

    static const uint8_t kWord[]  = {'W',0,'o',0,'r',0,'d',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
    static const uint8_t kXls1[]  = {'W',0,'o',0,'r',0,'k',0,'b',0,'o',0,'o',0,'k',0};
    static const uint8_t kXls2[]  = {'B',0,'o',0,'o',0,'k',0};
    static const uint8_t kPpt[]   = {'P',0,'o',0,'w',0,'e',0,'r',0,'P',0,'o',0,'i',0,'n',0,'t',0,' ',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
    static const uint8_t kVisio[] = {'V',0,'i',0,'s',0,'i',0,'o',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
    static const uint8_t kMsg[]   = {'_',0,'_',0,'s',0,'u',0,'b',0,'s',0,'t',0,'g',0,'1',0,'.',0,'0',0};

    if (has_bytes(b, n, kYozo1, sizeof(kYozo1)) || has_bytes(b, n, kYozo2, sizeof(kYozo2))) return {"eio", "application/x-yozo-eio"};
    if (has_bytes(b, n, kWpsDoc, sizeof(kWpsDoc))) return {"wps", "application/vnd.ms-works"};
    if (has_bytes(b, n, kWpsEt, sizeof(kWpsEt)))   return {"et", "application/kset"};
    if (has_bytes(b, n, kWpsDps, sizeof(kWpsDps))) return {"dps", "application/ksdps"};

    bool is_kso = has_bytes(b, n, kKso, sizeof(kKso)) || has_str(b, n, "Kingsoft");
    if (has_bytes(b, n, kWord, sizeof(kWord)))   return is_kso ? FileType{"wps", "application/kswps"} : FileType{"doc", "application/msword"};
    if (has_bytes(b, n, kXls1, sizeof(kXls1)) || has_bytes(b, n, kXls2, sizeof(kXls2)))
        return is_kso ? FileType{"et", "application/kset"} : FileType{"xls", "application/vnd.ms-excel"};
    if (has_bytes(b, n, kPpt, sizeof(kPpt)))     return is_kso ? FileType{"dps", "application/ksdps"} : FileType{"ppt", "application/vnd.ms-powerpoint"};

    if (has_bytes(b, n, kVisio, sizeof(kVisio))) return {"vsd", "application/vnd.visio"};
    if (has_bytes(b, n, kMsg, sizeof(kMsg)))     return {"msg", "application/vnd.ms-outlook"};
    return {"msi", "application/x-ole-storage"};
}

// 3. 细分 ISO BMFF "ftyp" 容器 (heic / avif / cr3 / m4a / m4v / mov / 3gp / mp4)
FileType classify_ftyp(const uint8_t* b, size_t n) {
    if (n < 12) return {"mp4", "video/mp4"};
    if (match(b, n, 8, "heic", 4) || match(b, n, 8, "heix", 4) ||
        match(b, n, 8, "hevc", 4) || match(b, n, 8, "mif1", 4)) return {"heic", "image/heic"};
    if (match(b, n, 8, "avif", 4) || match(b, n, 8, "avis", 4)) return {"avif", "image/avif"};
    if (match(b, n, 8, "crx ", 4)) return {"cr3", "image/x-canon-cr3"};
    if (match(b, n, 8, "M4A ", 4)) return {"m4a", "audio/mp4"};
    if (match(b, n, 8, "M4V ", 4)) return {"m4v", "video/x-m4v"};
    if (match(b, n, 8, "qt  ", 4)) return {"mov", "video/quicktime"};
    if (match(b, n, 8, "3gp", 3) || match(b, n, 8, "3g2", 3)) return {"3gp", "video/3gpp"};
    return {"mp4", "video/mp4"};
}

// 4. 细分 ELF 二进制类型 (AppImage / 可执行文件 elf / 动态库 so / 目标文件 o / 核心转储 core)
FileType classify_elf(const uint8_t* b, size_t n) {
    if (match(b, n, 8, "AI\x02", 3)) return {"appimage", "application/x-appimage"};
    if (n >= 18) {
        bool le = (b[5] != 2);
        uint16_t e_type = le ? static_cast<uint16_t>(b[16] | (b[17] << 8))
                             : static_cast<uint16_t>((b[16] << 8) | b[17]);
        if (e_type == 1) return {"o", "application/x-object"};
        if (e_type == 4) return {"core", "application/x-coredump"};
        // ET_DYN (3): 若无 PT_INTERP 动态链接器段则为纯共享库 .so，含 PT_INTERP 则为 PIE 可执行文件
        if (e_type == 3 && !has_str(b, n, "/ld-linux") && !has_str(b, n, "/ld-musl")) {
            return {"so", "application/x-sharedlib"};
        }
    }
    return {"elf", "application/x-executable"};
}

// 5. 细分 Windows PE 二进制 (exe / dll / sys)
FileType classify_pe(const uint8_t* b, size_t n) {
    if (n >= 0x40) {
        uint32_t pe_off = static_cast<uint32_t>(b[0x3C]) | (static_cast<uint32_t>(b[0x3D]) << 8) |
                          (static_cast<uint32_t>(b[0x3E]) << 16) | (static_cast<uint32_t>(b[0x3F]) << 24);
        if (pe_off + 24 <= n && match(b, n, pe_off, "PE\x00\x00", 4)) {
            uint16_t chars = static_cast<uint16_t>(b[pe_off + 22] | (b[pe_off + 23] << 8));
            if (chars & 0x2000) return {"dll", "application/x-msdownload"}; // IMAGE_FILE_DLL
            // 检查 OptionalHeader Subsystem == 1 (IMAGE_SUBSYSTEM_NATIVE -> .sys 驱动)
            if (pe_off + 94 <= n) {
                uint16_t subsys = static_cast<uint16_t>(b[pe_off + 92] | (b[pe_off + 93] << 8));
                if (subsys == 1) return {"sys", "application/x-ms-driver"};
            }
        }
    }
    return {"exe", "application/x-msdownload"};
}

// 6. 校验合法 UTF-8 / ASCII（容忍缓冲区末尾定长截断的多字节字符）
bool is_valid_utf8_text(const uint8_t* b, size_t n) {
    if (n == 0) return false;
    size_t i = 0;
    while (i < n) {
        uint8_t c = b[i];
        if (c == 0x00) return false;
        if (c < 0x80) {
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\b') return false;
            ++i;
        } else {
            size_t extra = 0;
            uint32_t cp = 0, min_cp = 0;
            if ((c & 0xE0) == 0xC0)      { extra = 1; cp = c & 0x1F; min_cp = 0x80; }
            else if ((c & 0xF0) == 0xE0) { extra = 2; cp = c & 0x0F; min_cp = 0x800; }
            else if ((c & 0xF8) == 0xF0) { extra = 3; cp = c & 0x07; min_cp = 0x10000; }
            else return false;

            if (i + extra >= n) {
                for (size_t j = i + 1; j < n; ++j)
                    if ((b[j] & 0xC0) != 0x80) return false;
                return true;
            }
            for (size_t j = 1; j <= extra; ++j) {
                if ((b[i + j] & 0xC0) != 0x80) return false;
                cp = (cp << 6) | (b[i + j] & 0x3F);
            }
            if (cp < min_cp || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
            i += 1 + extra;
        }
    }
    return true;
}

// 7. 检测 CSV / TSV 表格数据（要求至少 2 行，且前两行逗号或制表符数量一致且 >= 2）
FileType detect_tabular(const uint8_t* b, size_t n, size_t pos) {
    for (char sep : {'\t', ','}) {
        size_t c1 = 0, c2 = 0;
        bool in_quote = false;
        size_t i = pos;
        for (; i < n && b[i] != '\n'; ++i) {
            if (b[i] == '"') in_quote = !in_quote;
            else if (!in_quote && b[i] == static_cast<uint8_t>(sep)) ++c1;
        }
        if (c1 < 2 || i >= n) continue;
        ++i;
        for (; i < n && b[i] != '\n'; ++i) {
            if (b[i] == '"') in_quote = !in_quote;
            else if (!in_quote && b[i] == static_cast<uint8_t>(sep)) ++c2;
        }
        if (c1 == c2) {
            return sep == '\t' ? FileType{"tsv", "text/tab-separated-values"} : FileType{"csv", "text/csv"};
        }
    }
    return {"", ""};
}

// 8. 文本、证书、字幕、CAD 交换、邮件日历、构建配置与编程语言启发式细分
FileType classify_text(const uint8_t* b, size_t n) {
    size_t pos = match(b, n, 0, "\xEF\xBB\xBF", 3) ? 3 : 0;
    while (pos < n && std::isspace(b[pos])) ++pos;

    // 8.1 Shebang (#!)
    if (match(b, n, pos, "#!", 2)) {
        size_t eol = pos;
        while (eol < n && b[eol] != '\n' && b[eol] != '\r') ++eol;
        size_t line_len = eol - pos;
        if (has_str(b + pos, line_len, "python")) return {"py", "text/x-python"};
        if (has_str(b + pos, line_len, "node") || has_str(b + pos, line_len, "deno") || has_str(b + pos, line_len, "bun"))
            return {"js", "application/javascript"};
        if (has_str(b + pos, line_len, "ruby")) return {"rb", "text/x-ruby"};
        if (has_str(b + pos, line_len, "perl")) return {"pl", "text/x-perl"};
        if (has_str(b + pos, line_len, "php"))  return {"php", "text/x-php"};
        if (has_str(b + pos, line_len, "lua"))  return {"lua", "text/x-lua"};
        if (has_str(b + pos, line_len, "pwsh") || has_str(b + pos, line_len, "powershell")) return {"ps1", "application/x-powershell"};
        return {"sh", "text/x-shellscript"};
    }

    // 8.2 证书密钥、出版、CAD、3D、日历通讯录、字幕、邮件、固件 HEX
    if (match(b, n, pos, "-----BEGIN CERTIFICATE-----", 27)) return {"pem", "application/x-pem-file"};
    if (match(b, n, pos, "-----BEGIN ", 11) && has_str(b, n, "PRIVATE KEY-----")) return {"key", "application/x-pem-key"};
    if (match(b, n, pos, "-----BEGIN PGP ", 15)) return {"asc", "application/pgp-keys"};
    if (match(b, n, pos, "ssh-rsa ", 8) || match(b, n, pos, "ssh-ed25519 ", 12)) return {"pub", "text/plain"};
    if (match(b, n, pos, "%!PS-Adobe-", 11)) {
        return has_str(b, n, "EPSF-") ? FileType{"eps", "application/postscript"} : FileType{"ps", "application/postscript"};
    }
    if (match(b, n, pos, "0\nSECTION\n", 10) || match(b, n, pos, "0\r\nSECTION\r\n", 12)) return {"dxf", "image/vnd.dxf"};
    if (match(b, n, pos, "solid ", 6) && has_str(b, n, "facet normal")) return {"stl", "model/stl"};
    if ((match(b, n, pos, "# ", 2) || match(b, n, pos, "v ", 2) || match(b, n, pos, "mtllib ", 7)) &&
        has_str(b, n, "\nv ") && has_str(b, n, "\nf ")) return {"obj", "model/obj"};
    if (match(b, n, pos, "BEGIN:VCALENDAR", 15)) return {"ics", "text/calendar"};
    if (match(b, n, pos, "BEGIN:VCARD", 11)) return {"vcf", "text/vcard"};
    if (match(b, n, pos, "WEBVTT", 6)) return {"vtt", "text/vtt"};
    if ((match(b, n, pos, "1\n00:", 5) || match(b, n, pos, "1\r\n00:", 6)) && has_str(b, n, " --> ")) return {"srt", "application/x-subrip"};
    if (match(b, n, pos, "Windows Registry Editor", 23) || match(b, n, pos, "REGEDIT4", 8)) return {"reg", "text/x-ms-regedit"};
    if (match(b, n, pos, "From ", 5) && (has_str(b, n, "\nFrom: ") || has_str(b, n, "\r\nFrom: "))) return {"mbox", "application/mbox"};
    if ((match_ci(b, n, pos, "From: ") || match_ci(b, n, pos, "Return-Path: ") || match_ci(b, n, pos, "MIME-Version: ")) &&
        (has_str(b, n, "Subject: ") || has_str(b, n, "Content-Type: "))) {
        return {"eml", "message/rfc822"};
    }
    // Intel HEX 固件 (:10xxxx00... 或 :02000004...)
    if (b[pos] == ':' && n >= pos + 11 && std::isxdigit(b[pos + 1]) && std::isxdigit(b[pos + 2]) &&
        (has_str(b, n, ":00000001FF") || match(b, n, pos, ":02000004", 9) || match(b, n, pos, ":10", 3))) {
        return {"hex", "application/x-intel-hex"};
    }

    // 8.3 XML 及其衍生格式 (SVG / FB2 电子书 / Plist / Qt UI & QRC / RSS / Atom / OVF / VBOX)
    if (match_ci(b, n, pos, "<?xml") || match_ci(b, n, pos, "<!doctype")) {
        if (has_str(b, n, "<svg")) return {"svg", "image/svg+xml"};
        if (has_str(b, n, "<FictionBook")) return {"fb2", "application/x-fictionbook+xml"};
        if (has_str(b, n, "<plist") || has_str(b, n, "DTD PLIST")) return {"plist", "application/x-plist"};
        if (has_str(b, n, "<ui version=")) return {"ui", "application/x-designer"};
        if (has_str(b, n, "<RCC")) return {"qrc", "application/x-qt-resource"};
        if (has_str(b, n, "<rss")) return {"rss", "application/rss+xml"};
        if (has_str(b, n, "<feed") && has_str(b, n, "http://www.w3.org/2005/Atom")) return {"atom", "application/atom+xml"};
        if (has_str(b, n, "<Envelope") && has_str(b, n, "ovf")) return {"ovf", "application/x-ovf"};
        if (has_str(b, n, "<VirtualBox")) return {"vbox", "application/x-virtualbox-vbox"};
        if (match_ci(b, n, pos, "<!doctype html")) return {"html", "text/html"};
        return {"xml", "application/xml"};
    }
    if (match_ci(b, n, pos, "<svg")) return {"svg", "image/svg+xml"};
    if (match_ci(b, n, pos, "<html")) return {"html", "text/html"};
    if (match_ci(b, n, pos, "<ui version=")) return {"ui", "application/x-designer"};
    if (match_ci(b, n, pos, "<RCC")) return {"qrc", "application/x-qt-resource"};
    if (match_ci(b, n, pos, "<?php")) return {"php", "text/x-php"};
    if (match(b, n, pos, "---\n", 4) || match(b, n, pos, "---\r\n", 5)) return {"yaml", "application/x-yaml"};

    // 8.4 JSON / JSONL (NDJSON) / glTF / HAR / WebManifest
    if (pos < n && (b[pos] == '{' || b[pos] == '[')) {
        // 检测 JSONL: 第一行以 {...}\n 结束且第二行又以 { 开头
        if (b[pos] == '{') {
            size_t eol = pos;
            while (eol < n && b[eol] != '\n') ++eol;
            if (eol > pos && eol + 1 < n && (b[eol - 1] == '}' || (eol > pos + 1 && b[eol - 1] == '\r' && b[eol - 2] == '}'))) {
                size_t next = eol + 1;
                while (next < n && (b[next] == ' ' || b[next] == '\t')) ++next;
                if (next < n && b[next] == '{') return {"jsonl", "application/x-ndjson"};
            }
        }
        size_t p = pos + 1;
        while (p < n && std::isspace(b[p])) ++p;
        if (p < n && (b[p] == '"' || b[p] == '}' || b[p] == ']' || b[p] == '{' || b[p] == '[')) {
            if (has_str(b, n, "\"asset\"") && (has_str(b, n, "\"scenes\"") || has_str(b, n, "\"meshes\"")))
                return {"gltf", "model/gltf+json"};
            if (has_str(b, n, "\"log\"") && has_str(b, n, "\"entries\""))
                return {"har", "application/json"};
            if (has_str(b, n, "\"short_name\"") && has_str(b, n, "\"start_url\""))
                return {"webmanifest", "application/manifest+json"};
            return {"json", "application/json"};
        }
    }

    // 8.5 编程语言与配置语法特征扫描
    // WebAssembly Text (.wat)
    if (match(b, n, pos, "(module", 7)) return {"wat", "text/wasm"};
    // Protocol Buffers (.proto)
    if (has_str(b, n, "syntax = \"proto") || has_str(b, n, "syntax = 'proto")) return {"proto", "text/x-protobuf"};
    // GraphQL (.graphql)
    if ((match(b, n, pos, "type ", 5) || match(b, n, pos, "query ", 6) || match(b, n, pos, "mutation ", 9) || match(b, n, pos, "schema ", 7)) &&
        has_str(b, n, "{") && (has_str(b, n, ": String") || has_str(b, n, ": ID") || has_str(b, n, ": Int"))) {
        return {"graphql", "application/graphql"};
    }
    // Qt QML (.qml)
    if (match(b, n, pos, "import QtQuick", 14)) return {"qml", "text/x-qml"};
    // Windows 批处理 (.bat / .cmd)
    if (match_ci(b, n, pos, "@echo off") || match_ci(b, n, pos, "setlocal ")) return {"bat", "application/x-bat"};
    // PowerShell (.ps1)
    if (match_ci(b, n, pos, "param(") || has_str(b, n, "Write-Host ") || has_str(b, n, "$PSVersionTable")) return {"ps1", "application/x-powershell"};
    // 汇编 (.asm / .s)
    if (has_str(b, n, ".global ") || has_str(b, n, ".globl ") || has_str(b, n, "section .text") || has_str(b, n, ".intel_syntax")) {
        return {"asm", "text/x-asm"};
    }
    // CUDA (.cu) — 置于 C/C++ #include 检查之前，因为 CUDA 同样常包含 #include
    if (has_str(b, n, "__global__ ") || has_str(b, n, "__device__ ") || has_str(b, n, "cudaMalloc(")) return {"cu", "text/x-cuda"};
    // Objective-C (.m)
    if (has_str(b, n, "#import <") || has_str(b, n, "@interface ") || has_str(b, n, "@implementation ")) return {"m", "text/x-objcsrc"};
    // C# (.cs)
    if (has_str(b, n, "using System;") && has_str(b, n, "namespace ")) return {"cs", "text/x-csharp"};
    // Swift (.swift)
    if ((has_str(b, n, "import Foundation") || has_str(b, n, "import SwiftUI") || has_str(b, n, "import UIKit")) &&
        (has_str(b, n, "func ") || has_str(b, n, "struct ") || has_str(b, n, "let "))) return {"swift", "text/x-swift"};
    // Kotlin (.kt)
    if (has_str(b, n, "fun main(") || (match(b, n, pos, "package ", 8) && has_str(b, n, "fun ") && has_str(b, n, "val "))) {
        return {"kt", "text/x-kotlin"};
    }
    // C / C++
    if (has_str(b, n, "#include <") || has_str(b, n, "#include \"") || has_str(b, n, "#pragma once")) {
        if (has_str(b, n, "namespace ") || has_str(b, n, "template<") || has_str(b, n, "template <") ||
            has_str(b, n, "std::") || has_str(b, n, "class ") || has_str(b, n, "<iostream>")) {
            return {"cpp", "text/x-c++src"};
        }
        return {"c", "text/x-csrc"};
    }
    // Rust
    if (has_str(b, n, "fn main()") || (has_str(b, n, "pub fn ") && has_str(b, n, "let mut ")) || has_str(b, n, "#[derive(")) {
        return {"rs", "text/x-rust"};
    }
    // Java
    if ((has_str(b, n, "public class ") || has_str(b, n, "public interface ") || has_str(b, n, "import java.")) &&
        (has_str(b, n, ";") || has_str(b, n, "public static void main"))) {
        return {"java", "text/x-java-source"};
    }
    // Go
    if (match(b, n, pos, "package ", 8) && (has_str(b, n, "func ") || has_str(b, n, "import \"") || has_str(b, n, "import ("))) {
        return {"go", "text/x-go"};
    }
    // Python / Ruby / Lua
    if (has_str(b, n, "def ") && (has_str(b, n, "import ") || has_str(b, n, "from ") || has_str(b, n, "if __name__"))) {
        return {"py", "text/x-python"};
    }
    if (has_str(b, n, "require '") && has_str(b, n, "def ") && has_str(b, n, "end\n")) return {"rb", "text/x-ruby"};
    if (has_str(b, n, "local ") && has_str(b, n, "function ") && has_str(b, n, "end")) return {"lua", "text/x-lua"};
    // TypeScript / JavaScript
    if (has_str(b, n, "interface ") && (has_str(b, n, "export ") || has_str(b, n, ": string") || has_str(b, n, ": number"))) {
        return {"ts", "application/typescript"};
    }
    if (has_str(b, n, "const ") || has_str(b, n, "function ") || has_str(b, n, "export default ") || has_str(b, n, "module.exports")) {
        return {"js", "application/javascript"};
    }
    // SQL
    if (match_ci(b, n, pos, "CREATE TABLE ") || match_ci(b, n, pos, "SELECT ") ||
        match_ci(b, n, pos, "INSERT INTO ") || match_ci(b, n, pos, "-- SQL")) {
        return {"sql", "application/sql"};
    }
    // CSS
    if (has_str(b, n, "@media ") || (has_str(b, n, "{") && has_str(b, n, "color:") && has_str(b, n, ";"))) {
        return {"css", "text/css"};
    }
    // Markdown
    if (match(b, n, pos, "# ", 2) && (has_str(b, n, "\n## ") || has_str(b, n, "\n```") || has_str(b, n, "\n- "))) {
        return {"md", "text/markdown"};
    }
    // VMware VMX
    if (has_str(b, n, ".encoding =") && has_str(b, n, "virtualHW.version =")) return {"vmx", "application/x-vmware-vmx"};
    // TOML / INI
    if (b[pos] == '[' && has_str(b, n, "]\n") && has_str(b, n, "=")) {
        if (has_str(b, n, " = \"") || has_str(b, n, " = [") || has_str(b, n, "[[")) return {"toml", "application/toml"};
        return {"ini", "text/plain"};
    }
    // .env 环境变量配置 (KEY=VALUE 且键名全大写加下划线)
    if (std::isupper(b[pos])) {
        size_t k = pos;
        while (k < n && (std::isupper(b[k]) || std::isdigit(b[k]) || b[k] == '_')) ++k;
        if (k > pos + 2 && k < n && b[k] == '=') return {"env", "text/plain"};
    }
    // CSV / TSV 表格交换
    FileType tab = detect_tabular(b, n, pos);
    if (tab.ext[0] != '\0') return tab;

    return {"txt", "text/plain"};
}

} // namespace

FileType detect_bytes(const uint8_t* b, size_t n) {
    if (!b || n == 0) return {"empty", "inode/x-empty"};

    // 1. 图像与相机 RAW 格式 (PNG / JPG / GIF / WEBP / BMP / CR2 / ORF / RW2 / RAF / DNG / TIFF / ICO / PSD / PSB / JXL / JP2 / EXR / HDR / DDS / BPG)
    if (match(b, n, 0, "\x89PNG\r\n\x1a\n", 8)) return {"png", "image/png"};
    if (match(b, n, 0, "\xFF\xD8\xFF", 3)) return {"jpg", "image/jpeg"};
    if (match(b, n, 0, "GIF87a", 6) || match(b, n, 0, "GIF89a", 6)) return {"gif", "image/gif"};
    if (match(b, n, 0, "RIFF", 4) && match(b, n, 8, "WEBP", 4)) return {"webp", "image/webp"};
    if (match(b, n, 0, "BM", 2)) return {"bmp", "image/bmp"};
    if (match(b, n, 0, "II*\x00", 4) && match(b, n, 8, "CR\x02\x00", 4)) return {"cr2", "image/x-canon-cr2"};
    if (match(b, n, 0, "IIRO\x08\x00\x00\x00", 8) || match(b, n, 0, "IIRS\x08\x00\x00\x00", 8)) return {"orf", "image/x-olympus-orf"};
    if (match(b, n, 0, "IIU\x00", 4)) return {"rw2", "image/x-panasonic-rw2"};
    if (match(b, n, 0, "FUJIFILMCCD-RAW ", 16)) return {"raf", "image/x-fuji-raf"};
    if (match(b, n, 0, "II*\x00", 4) || match(b, n, 0, "MM\x00*", 4)) return {"tif", "image/tiff"};
    if (match(b, n, 0, "\x00\x00\x01\x00", 4)) return {"ico", "image/x-icon"};
    if (match(b, n, 0, "\x00\x00\x02\x00", 4)) return {"cur", "image/x-win-bitmap"};
    if (match(b, n, 0, "8BPS\x00\x02", 6)) return {"psb", "image/vnd.adobe.photoshop"};
    if (match(b, n, 0, "8BPS", 4)) return {"psd", "image/vnd.adobe.photoshop"};
    if (match(b, n, 0, "\xFF\x0A", 2) || match(b, n, 0, "\x00\x00\x00\x0CJXL \x0D\x0A\x87\x0A", 12)) return {"jxl", "image/jxl"};
    if (match(b, n, 0, "\x00\x00\x00\x0CjP  \r\n\x87\n", 12)) return {"jp2", "image/jp2"};
    if (match(b, n, 0, "\x76\x2F\x31\x01", 4)) return {"exr", "image/x-exr"};
    if (match(b, n, 0, "#?RADIANCE\n", 11) || match(b, n, 0, "#?RGBE\n", 7)) return {"hdr", "image/vnd.radiance"};
    if (match(b, n, 0, "DDS ", 4)) return {"dds", "image/vnd-ms.dds"};
    if (match(b, n, 0, "BPG\xFB", 4)) return {"bpg", "image/bpg"};

    // 2. 文档、Office、国产文献、电子书与帮助文档 (PDF / RTF / CHM / HLP / CAJ / KDH / CEB / MOBI / DJVU / INDD / OLE2 / ZIP)
    if (match(b, n, 0, "%PDF-", 5)) return {"pdf", "application/pdf"};
    if (match(b, n, 0, "{\\rtf", 5)) return {"rtf", "application/rtf"};
    if (match(b, n, 0, "ITSF\x03\x00\x00\x00", 8)) return {"chm", "application/vnd.ms-htmlhelp"};
    if (match(b, n, 0, "\x3F\x5F\x03\x00", 4)) return {"hlp", "application/winhlp"};
    if (match(b, n, 0, "CAJ", 3) || match(b, n, 0, "HN\x00\x00", 4)) return {"caj", "application/x-caj"};
    if (match(b, n, 0, "KDH ", 4)) return {"kdh", "application/x-kdh"};
    if (match(b, n, 0, "Founder Apabi", 13)) return {"ceb", "application/vnd.apabi.ceb"};
    if (match(b, n, 60, "BOOKMOBI", 8)) return {"mobi", "application/x-mobipocket-ebook"};
    if (match(b, n, 0, "AT&TFORM", 8) && (match(b, n, 12, "DJVU", 4) || match(b, n, 12, "DJVM", 4))) return {"djvu", "image/vnd.djvu"};
    if (match(b, n, 0, "\x06\x06\xED\xF5\xD8\x1D\x46\xE5\xBD\x31\xEF\xE7\xFE\x74\xB7\x1D", 16)) return {"indd", "application/x-indesign"};
    if (match(b, n, 0, "\xC5\xD0\xD3\xC6", 4)) return {"eps", "application/postscript"};
    if (match(b, n, 0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8)) return classify_ole2(b, n);
    if (match(b, n, 0, "PK\x03\x04", 4) || match(b, n, 0, "PK\x05\x06", 4)) return classify_zip(b, n);

    // 3. CAD、3D 模型与科研天文地理 (DWG / GLB / BLEND / FBX / 3DS / SHP / FITS)
    if (match(b, n, 0, "AC10", 4) && n >= 6 && std::isdigit(b[4]) && std::isdigit(b[5])) return {"dwg", "image/vnd.dwg"};
    if (match(b, n, 0, "glTF", 4)) return {"glb", "model/gltf-binary"};
    if (match(b, n, 0, "BLENDER", 7)) return {"blend", "application/x-blender"};
    if (match(b, n, 0, "Kaydara FBX Binary  \x00", 21)) return {"fbx", "application/octet-stream"};
    if (match(b, n, 0, "\x4D\x4D", 2) && n >= 10 && b[5] == 0x00 && (b[6] == 0x02 || b[6] == 0x3D)) return {"3ds", "image/x-3ds"};
    if (match(b, n, 0, "\x00\x00\x27\x0A\x00\x00\x00\x00", 8) && match(b, n, 24, "\x00\x00\x03\xE8", 4)) return {"shp", "application/x-esri-shape"};
    if (match(b, n, 0, "SIMPLE  =                    T", 30)) return {"fits", "image/fits"};

    // 4. 大数据、AI 模型、科学数据与数据库 (Parquet / ORC / Avro / Arrow / HDF5 / NetCDF / NPY / GGUF / SQLite / MDF / Access / Redis / PST / KDBX)
    if (match(b, n, 0, "PAR1", 4)) return {"parquet", "application/vnd.apache.parquet"};
    if (match(b, n, 0, "ORC", 3) && n >= 4 && b[3] < 0x20) return {"orc", "application/vnd.apache.orc"};
    if (match(b, n, 0, "Obj\x01", 4)) return {"avro", "application/vnd.apache.avro"};
    if (match(b, n, 0, "ARROW1\x00\x00", 8)) return {"arrow", "application/vnd.apache.arrow.file"};
    if (match(b, n, 0, "FEA1", 4)) return {"feather", "application/vnd.apache.arrow.feather"};
    if (match(b, n, 0, "\x89HDF\r\n\x1a\n", 8)) return {"h5", "application/x-hdf5"};
    if (match(b, n, 0, "CDF\x01", 4) || match(b, n, 0, "CDF\x02", 4)) return {"nc", "application/x-netcdf"};
    if (match(b, n, 0, "\x93NUMPY", 6)) return {"npy", "application/x-numpy-data"};
    if (match(b, n, 0, "GGUF", 4)) return {"gguf", "application/x-gguf"};
    if (match(b, n, 0, "SQLite format 3\x00", 16)) return {"sqlite", "application/vnd.sqlite3"};
    if (match(b, n, 0, "\x01\x0F\x00\x00", 4) && n >= 16) return {"mdf", "application/x-mssql"};
    if (match(b, n, 4, "Standard Jet DB", 15)) return {"mdb", "application/x-msaccess"};
    if (match(b, n, 4, "Standard ACE DB", 15)) return {"accdb", "application/x-msaccess"};
    if (match(b, n, 0, "REDIS00", 7)) return {"rdb", "application/x-redis-rdb"};
    if (match(b, n, 0, "!BDN", 4)) return {"pst", "application/vnd.ms-outlook-pst"};
    if (match(b, n, 0, "\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5", 8)) return {"kdbx", "application/x-keepass2"};
    if (match(b, n, 0, "\x3F\xD7\x6C\x17", 4)) return {"cfs", "application/x-lucene"};

    // 5. 压缩包、安装包与磁盘镜像
    if (match(b, n, 0, "Rar!\x1A\x07\x01\x00", 8) || match(b, n, 0, "Rar!\x1A\x07\x00", 7)) return {"rar", "application/x-rar-compressed"};
    if (match(b, n, 0, "7z\xBC\xAF\x27\x1C", 6)) return {"7z", "application/x-7z-compressed"};
    if (match(b, n, 0, "\x1F\x8B\x08", 3)) return {"gz", "application/gzip"};
    if (match(b, n, 0, "BZh", 3)) return {"bz2", "application/x-bzip2"};
    if (match(b, n, 0, "\xFD" "7zXZ\x00", 6)) return {"xz", "application/x-xz"};
    if (match(b, n, 0, "\x28\xB5\x2F\xFD", 4)) return {"zst", "application/zstd"};
    if (match(b, n, 0, "\x04\x22\x4D\x18", 4)) return {"lz4", "application/x-lz4"};
    if (match(b, n, 0, "\x89LZO\x00\r\n\x1A\n", 9)) return {"lzo", "application/x-lzop"};
    if (match(b, n, 0, "LZIP", 4)) return {"lz", "application/x-lzip"};
    if (match(b, n, 0, "\x1F\x9D", 2) || match(b, n, 0, "\x1F\xA0", 2)) return {"Z", "application/x-compress"};
    if (match(b, n, 0, "MSCF", 4)) return {"cab", "application/vnd.ms-cab-compressed"};
    if (match(b, n, 0, "MSWIM\x00\x00\x00", 8)) return {"wim", "application/x-ms-wim"};
    if (match(b, n, 0, "xar!", 4)) return {"xar", "application/x-xar"};
    if (match(b, n, 0, "Cr24", 4)) return {"crx", "application/x-chrome-extension"};
    if (match(b, n, 0, "!<arch>\ndebian", 14)) return {"deb", "application/vnd.debian.binary-package"};
    if (match(b, n, 0, "!<arch>\n", 8)) return {"a", "application/x-archive"};
    if (match(b, n, 0, "\xED\xAB\xEE\xDB", 4)) return {"rpm", "application/x-rpm"};
    if (match(b, n, 0, "070701", 6) || match(b, n, 0, "070702", 6) || match(b, n, 0, "070707", 6)) return {"cpio", "application/x-cpio"};
    if (match(b, n, 257, "ustar", 5)) return {"tar", "application/x-tar"};
    if (match(b, n, 0, "hsqs", 4)) return {"squashfs", "application/vnd.squashfs"};
    if (match(b, n, 0, "QFI\xFB", 4)) return {"qcow2", "application/x-qemu-disk"};
    if (match(b, n, 0, "KDMV", 4)) return {"vmdk", "application/x-vmdk-disk"};
    if (match(b, n, 0, "conectix", 8)) return {"vhd", "application/x-vhd-disk"};
    if (match(b, n, 0, "vhdxfile", 8)) return {"vhdx", "application/x-vhdx-disk"};
    if (match(b, n, 0, "<<< Oracle VM VirtualBox Disk Image >>>", 39)) return {"vdi", "application/x-vdi-disk"};
    if (match(b, n, 0, "b0VIM ", 6)) return {"swp", "application/x-vim-swap"};
    if (match(b, n, 0, "ANDROID BACKUP\n", 15)) return {"ab", "application/x-android-backup"};
    if (match(b, n, 0, "bplist00", 8)) return {"plist", "application/x-bplist"};
    if (match(b, n, 0, "regf", 4)) return {"hiv", "application/x-ms-registry"};
    if (match(b, n, 0x8001, "CD001", 5) || match(b, n, 0x8801, "CD001", 5) || match(b, n, 0x9001, "CD001", 5)) {
        return {"iso", "application/x-iso9660-image"};
    }

    // 6. 字体 (TTF / OTF / WOFF / WOFF2)
    if (match(b, n, 0, "\x00\x01\x00\x00\x00", 5)) return {"ttf", "font/ttf"};
    if (match(b, n, 0, "OTTO", 4)) return {"otf", "font/otf"};
    if (match(b, n, 0, "wOFF", 4)) return {"woff", "font/woff"};
    if (match(b, n, 0, "wOF2", 4)) return {"woff2", "font/woff2"};

    // 7. 可执行文件、库、目标文件、调试符号与抓包 (ELF/SO/O/Core/AppImage, EXE/DLL/SYS, Mach-O, PDB, PYC, WASM, LNK, DMP, EVTX, PCAP, DER)
    if (match(b, n, 0, "\x7F" "ELF", 4)) return classify_elf(b, n);
    if (match(b, n, 0, "MZ", 2)) return classify_pe(b, n);
    if (match(b, n, 0, "\xFE\xED\xFA\xCE", 4) || match(b, n, 0, "\xFE\xED\xFA\xCF", 4) ||
        match(b, n, 0, "\xCE\xFA\xED\xFE", 4) || match(b, n, 0, "\xCF\xFA\xED\xFE", 4)) return {"macho", "application/x-mach-binary"};
    if (match(b, n, 0, "Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53\x00\x00\x00", 32)) return {"pdb", "application/x-ms-pdb"};
    if (match(b, n, 0, "\xCA\xFE\xBA\xBE", 4)) return {"class", "application/java-vm"};
    if (match(b, n, 0, "dex\n03", 6)) return {"dex", "application/vnd.android.dex"};
    if (match(b, n, 0, "\x00" "asm", 4)) return {"wasm", "application/wasm"};
    if (n >= 16 && b[2] == 0x0D && b[3] == 0x0A && b[0] >= 0x42 && b[1] == 0x0D) return {"pyc", "application/x-python-code"};
    if (match(b, n, 0, "\x4C\x00\x00\x00\x01\x14\x02\x00", 8)) return {"lnk", "application/x-ms-shortcut"};
    if (match(b, n, 0, "MDMP", 4) || match(b, n, 0, "PAGEDUMP", 8)) return {"dmp", "application/x-dmp"};
    if (match(b, n, 0, "ElfFile\x00", 8)) return {"evtx", "application/x-ms-evtx"};
    if (match(b, n, 0, "\xD4\xC3\xB2\xA1", 4) || match(b, n, 0, "\xA1\xB2\xC3\xD4", 4)) return {"pcap", "application/vnd.tcpdump.pcap"};
    if (match(b, n, 0, "\x0A\x0D\x0D\x0A", 4)) return {"pcapng", "application/x-pcapng"};
    // X.509 DER 二进制证书 (ASN.1 SEQUENCE: 0x30 0x82 len_hi len_lo 0x30 0x82)
    if (n >= 8 && b[0] == 0x30 && b[1] == 0x82 && b[4] == 0x30 && b[5] == 0x82) return {"der", "application/x-x509-ca-cert"};

    // 8. UTF-16 / UTF-32 BOM 文本（置于裸 MP3 帧同步检测前，避免 0xFF 0xFE 冲突）
    if (match(b, n, 0, "\xFF\xFE\x00\x00", 4) || match(b, n, 0, "\x00\x00\xFE\xFF", 4)) return {"txt", "text/plain; charset=utf-32"};
    if (match(b, n, 0, "\xFF\xFE", 2) || match(b, n, 0, "\xFE\xFF", 2)) return {"txt", "text/plain; charset=utf-16"};

    // 9. 音视频与流媒体容器 (WAV / AVI / AIFF / DSF / DFF / AMR / APE / WV / ASF(WMV) / MXF / MPG / TS / M2TS / OGG/OPUS/OGV / AAC / MP3 / FLAC / MIDI / FLV / MKV / WEBM / MP4)
    if (match(b, n, 0, "RIFF", 4) && match(b, n, 8, "WAVE", 4)) return {"wav", "audio/x-wav"};
    if (match(b, n, 0, "RIFF", 4) && match(b, n, 8, "AVI ", 4)) return {"avi", "video/x-msvideo"};
    if (match(b, n, 0, "FORM", 4) && (match(b, n, 8, "AIFF", 4) || match(b, n, 8, "AIFC", 4))) return {"aiff", "audio/x-aiff"};
    if (match(b, n, 0, "DSD ", 4)) return {"dsf", "audio/x-dsf"};
    if (match(b, n, 0, "FRM8", 4) && match(b, n, 12, "DSD ", 4)) return {"dff", "audio/x-dff"};
    if (match(b, n, 0, "#!AMR", 5)) return {"amr", "audio/amr"};
    if (match(b, n, 0, "MAC ", 4)) return {"ape", "audio/x-ape"};
    if (match(b, n, 0, "wvpk", 4)) return {"wv", "audio/x-wavpack"};
    if (match(b, n, 0, "\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C", 16)) return {"wmv", "video/x-ms-asf"};
    if (match(b, n, 0, "\x06\x0E\x2B\x34\x02\x05\x01\x01\x0D\x01\x02\x01\x01\x02", 14)) return {"mxf", "application/mxf"};
    if (match(b, n, 0, "\x00\x00\x01\xBA", 4) || match(b, n, 0, "\x00\x00\x01\xB3", 4)) return {"mpg", "video/mpeg"};
    // MPEG-TS 视频流 (.ts): 每 188 字节出现同步字 0x47；BDAV (.m2ts): 每 192 字节偏移 4 处出现 0x47
    if (n >= 377 && b[0] == 0x47 && b[188] == 0x47 && b[376] == 0x47) return {"ts", "video/mp2t"};
    if (n >= 389 && b[4] == 0x47 && b[196] == 0x47 && b[388] == 0x47) return {"m2ts", "video/mp2t"};
    if (n >= 2 && b[0] == 0xFF && (b[1] == 0xF1 || b[1] == 0xF9)) return {"aac", "audio/aac"};
    if (match(b, n, 0, "ID3", 3) || (n >= 2 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0 && (b[1] & 0x18) != 0x08 && (b[1] & 0x06) != 0)) return {"mp3", "audio/mpeg"};
    if (match(b, n, 0, "fLaC", 4)) return {"flac", "audio/x-flac"};
    if (match(b, n, 0, "OggS", 4)) {
        if (match(b, n, 28, "OpusHead", 8)) return {"opus", "audio/opus"};
        if (match(b, n, 28, "\x80theora", 7)) return {"ogv", "video/ogg"};
        return {"ogg", "audio/ogg"};
    }
    if (match(b, n, 0, "MThd", 4)) return {"mid", "audio/midi"};
    if (match(b, n, 0, "FLV\x01", 4)) return {"flv", "video/x-flv"};
    if (match(b, n, 0, "\x1A\x45\xDF\xA3", 4)) {
        if (has_str(b, n, "webm")) return {"webm", "video/webm"};
        return {"mkv", "video/x-matroska"};
    }
    if (match(b, n, 4, "ftyp", 4)) return classify_ftyp(b, n);

    // 10. UTF-8 (含或不含 BOM) / ASCII 启发式扫描与源码细分
    if (match(b, n, 0, "\xEF\xBB\xBF", 3) || is_valid_utf8_text(b, n)) {
        return classify_text(b, n);
    }

    return {"unknown", "application/octet-stream"};
}

FileType detect_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {"error", "inode/x-empty"};
    std::streamsize size = f.tellg();
    if (size <= 0) return {"empty", "inode/x-empty"};

    size_t head_len = static_cast<size_t>(std::min<std::streamsize>(size, 4096));
    std::vector<uint8_t> buf(head_len);
    f.seekg(0, std::ios::beg);
    f.read(reinterpret_cast<char*>(buf.data()), head_len);

    if (match(buf.data(), buf.size(), 0, "PK\x03\x04", 4)) {
        FileType ft = classify_zip(buf.data(), buf.size());
        if (std::strcmp(ft.ext, "zip") == 0 && size > 4096) {
            size_t tail_len = static_cast<size_t>(std::min<std::streamsize>(size, 65536));
            std::vector<uint8_t> tail(tail_len);
            f.seekg(size - tail_len, std::ios::beg);
            f.read(reinterpret_cast<char*>(tail.data()), tail_len);
            return classify_zip(tail.data(), tail.size());
        }
        return ft;
    }

    if (match(buf.data(), buf.size(), 0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8)) {
        size_t ole_len = static_cast<size_t>(std::min<std::streamsize>(size, 65536));
        std::vector<uint8_t> ole_buf(ole_len);
        f.seekg(0, std::ios::beg);
        f.read(reinterpret_cast<char*>(ole_buf.data()), ole_len);
        FileType ft = classify_ole2(ole_buf.data(), ole_buf.size());
        if (std::strcmp(ft.ext, "msi") == 0 && size > 65536) {
            f.seekg(size - 65536, std::ios::beg);
            f.read(reinterpret_cast<char*>(ole_buf.data()), 65536);
            return classify_ole2(ole_buf.data(), ole_buf.size());
        }
        return ft;
    }

    FileType ft = detect_bytes(buf.data(), buf.size());

    if (std::strcmp(ft.ext, "unknown") == 0) {
        if (size > 0x8006) {
            char cd_sig[5] = {0};
            const std::streamoff offsets[] = {0x8001, 0x8801, 0x9001};
            for (std::streamoff off : offsets) {
                if (size >= off + 5) {
                    f.seekg(off, std::ios::beg);
                    f.read(cd_sig, 5);
                    if (std::memcmp(cd_sig, "CD001", 5) == 0) {
                        return {"iso", "application/x-iso9660-image"};
                    }
                }
            }
        }
        if (size >= 512) {
            char koly[4] = {0};
            f.seekg(size - 512, std::ios::beg);
            f.read(koly, 4);
            if (std::memcmp(koly, "koly", 4) == 0) {
                return {"dmg", "application/x-apple-diskimage"};
            }
        }
    }

    return ft;
}

} // namespace ftype
