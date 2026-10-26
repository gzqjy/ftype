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

// 1. 细分 ZIP 容器 (OFD / UOF / 永中 EIO / OOXML / ODF / EPUB / APK / JAR / IPA / VSDX)
FileType classify_zip(const uint8_t* b, size_t n) {
    if (match(b, n, 30, "mimetype", 8)) {
        if (match(b, n, 38, "application/epub+zip", 20)) return {"epub", "application/epub+zip"};
        if (match(b, n, 38, "application/vnd.oasis.opendocument.text", 39)) return {"odt", "application/vnd.oasis.opendocument.text"};
        if (match(b, n, 38, "application/vnd.oasis.opendocument.spreadsheet", 46)) return {"ods", "application/vnd.oasis.opendocument.spreadsheet"};
        if (match(b, n, 38, "application/vnd.oasis.opendocument.presentation", 47)) return {"odp", "application/vnd.oasis.opendocument.presentation"};
    }
    // 中国国家版式文档标准 OFD (GB/T 33190): 根目录固定含 OFD.xml 及 Doc_0/
    if (has_str(b, n, "OFD.xml")) return {"ofd", "application/ofd"};
    // 永中 Office 集成文档 (.eio / .eiop): 内部含 Yozo_ Office 特征条目或 Workbook_ / Workpg_ 流
    if (has_str(b, n, "Yozo") || has_str(b, n, "yozo") || has_str(b, n, "EIO_")) return {"eio", "application/x-yozo-eio"};
    // 中文办公软件文档标准 UOF (GB/T 20916): 开放中文电子文档 (uof.xml / uot / uos / uop)
    if (has_str(b, n, "uof.xml") || (has_str(b, n, "content.xml") && has_str(b, n, "uof:"))) return {"uof", "application/vnd.uof"};
    // OOXML (Word / Excel / PowerPoint / Visio)
    if (has_str(b, n, "word/")) return {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"};
    if (has_str(b, n, "xl/")) return {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"};
    if (has_str(b, n, "ppt/")) return {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"};
    if (has_str(b, n, "visio/")) return {"vsdx", "application/vnd.ms-visio.drawing"};
    if (has_str(b, n, "AndroidManifest.xml") || has_str(b, n, "classes.dex")) return {"apk", "application/vnd.android.package-archive"};
    if (has_str(b, n, "Payload/")) return {"ipa", "application/x-ios-app"};
    if (has_str(b, n, "META-INF/")) return {"jar", "application/java-archive"};
    return {"zip", "application/zip"};
}

// 2. 细分 OLE2 复合文档 (WPS 专用格式 wps/et/dps、永中 eio 及 MS Office doc/xls/ppt/vsd/msg/msi)
// OLE2 Directory Entry 中的流名称以 UTF-16LE 编码存储
FileType classify_ole2(const uint8_t* b, size_t n) {
    // 金山 WPS 专属标识流（WPS 文字含 WordDocument + KSOProductBuildVer/WPS 专属流；ET 表格与 DPS 演示亦有专属标识）
    static const uint8_t kWpsDoc[] = {'W',0,'P',0,'S',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
    static const uint8_t kWpsEt[]  = {'E',0,'T',0,'W',0,'o',0,'r',0,'k',0,'b',0,'o',0,'o',0,'k',0};
    static const uint8_t kWpsDps[] = {'D',0,'P',0,'S',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
    static const uint8_t kKso[]    = {'K',0,'S',0,'O',0,'P',0,'r',0,'o',0,'d',0,'u',0,'c',0,'t',0};
    // 永中 Office (Yozo/Evermore Integrated Office) OLE2 集成文档流名
    static const uint8_t kYozo1[]  = {'Y',0,'o',0,'z',0,'o',0};
    static const uint8_t kYozo2[]  = {'E',0,'I',0,'O',0,'_',0};

    // 微软 Office 标准流名
    static const uint8_t kWord[]  = {'W',0,'o',0,'r',0,'d',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
    static const uint8_t kXls1[]  = {'W',0,'o',0,'r',0,'k',0,'b',0,'o',0,'o',0,'k',0};
    static const uint8_t kXls2[]  = {'B',0,'o',0,'o',0,'k',0};
    static const uint8_t kPpt[]   = {'P',0,'o',0,'w',0,'e',0,'r',0,'P',0,'o',0,'i',0,'n',0,'t',0,' ',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
    static const uint8_t kVisio[] = {'V',0,'i',0,'s',0,'i',0,'o',0,'D',0,'o',0,'c',0,'u',0,'m',0,'e',0,'n',0,'t',0};
    static const uint8_t kMsg[]   = {'_',0,'_',0,'s',0,'u',0,'b',0,'s',0,'t',0,'g',0,'1',0,'.',0,'0',0};

    // 2.1 优先匹配永中 Office 与金山 WPS 专用标识
    if (has_bytes(b, n, kYozo1, sizeof(kYozo1)) || has_bytes(b, n, kYozo2, sizeof(kYozo2))) return {"eio", "application/x-yozo-eio"};
    if (has_bytes(b, n, kWpsDoc, sizeof(kWpsDoc))) return {"wps", "application/vnd.ms-works"};
    if (has_bytes(b, n, kWpsEt, sizeof(kWpsEt)))   return {"et", "application/kset"};
    if (has_bytes(b, n, kWpsDps, sizeof(kWpsDps))) return {"dps", "application/ksdps"};

    // 若同时含有 KSOProductBuildVer 与 Word/Workbook/PowerPoint 流，则判定为金山 wps/et/dps
    bool is_kso = has_bytes(b, n, kKso, sizeof(kKso)) || has_str(b, n, "Kingsoft");
    if (has_bytes(b, n, kWord, sizeof(kWord)))   return is_kso ? FileType{"wps", "application/kswps"} : FileType{"doc", "application/msword"};
    if (has_bytes(b, n, kXls1, sizeof(kXls1)) || has_bytes(b, n, kXls2, sizeof(kXls2)))
        return is_kso ? FileType{"et", "application/kset"} : FileType{"xls", "application/vnd.ms-excel"};
    if (has_bytes(b, n, kPpt, sizeof(kPpt)))     return is_kso ? FileType{"dps", "application/ksdps"} : FileType{"ppt", "application/vnd.ms-powerpoint"};

    if (has_bytes(b, n, kVisio, sizeof(kVisio))) return {"vsd", "application/vnd.visio"};
    if (has_bytes(b, n, kMsg, sizeof(kMsg)))     return {"msg", "application/vnd.ms-outlook"};
    return {"msi", "application/x-ole-storage"};
}

// 3. 细分 ISO BMFF "ftyp" 容器 (heic / avif / cr3 / m4a / mov / 3gp / mp4)
FileType classify_ftyp(const uint8_t* b, size_t n) {
    if (n < 12) return {"mp4", "video/mp4"};
    if (match(b, n, 8, "heic", 4) || match(b, n, 8, "heix", 4) ||
        match(b, n, 8, "hevc", 4) || match(b, n, 8, "mif1", 4)) return {"heic", "image/heic"};
    if (match(b, n, 8, "avif", 4) || match(b, n, 8, "avis", 4)) return {"avif", "image/avif"};
    if (match(b, n, 8, "crx ", 4)) return {"cr3", "image/x-canon-cr3"};
    if (match(b, n, 8, "M4A ", 4)) return {"m4a", "audio/mp4"};
    if (match(b, n, 8, "qt  ", 4)) return {"mov", "video/quicktime"};
    if (match(b, n, 8, "3gp", 3))  return {"3gp", "video/3gpp"};
    return {"mp4", "video/mp4"};
}

// 4. 校验合法 UTF-8 / ASCII（容忍缓冲区末尾定长截断的多字节字符）
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

// 5. 文本、数据与编程语言启发式细分
FileType classify_text(const uint8_t* b, size_t n) {
    size_t pos = match(b, n, 0, "\xEF\xBB\xBF", 3) ? 3 : 0;
    while (pos < n && std::isspace(b[pos])) ++pos;

    // 5.1 Shebang (#!) 细分语言解释器
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
        return {"sh", "text/x-shellscript"};
    }

    // 5.2 标记语言与配置文件
    if (match_ci(b, n, pos, "<?xml")) {
        return has_str(b, n, "<svg") ? FileType{"svg", "image/svg+xml"} : FileType{"xml", "application/xml"};
    }
    if (match_ci(b, n, pos, "<svg")) return {"svg", "image/svg+xml"};
    if (match_ci(b, n, pos, "<!doctype html") || match_ci(b, n, pos, "<html")) return {"html", "text/html"};
    if (match_ci(b, n, pos, "<?php")) return {"php", "text/x-php"};
    if (match(b, n, pos, "---\n", 4) || match(b, n, pos, "---\r\n", 5)) return {"yaml", "application/x-yaml"};

    // JSON
    if (pos < n && (b[pos] == '{' || b[pos] == '[')) {
        size_t p = pos + 1;
        while (p < n && std::isspace(b[p])) ++p;
        if (p < n && (b[p] == '"' || b[p] == '}' || b[p] == ']' || b[p] == '{' || b[p] == '['))
            return {"json", "application/json"};
    }

    // 5.3 编程语言语法特征扫描
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
    // Java (置于 Go 之前，因两者均可由 package + import 开头，但 Java 带分号或 public class)
    if ((has_str(b, n, "public class ") || has_str(b, n, "public interface ") || has_str(b, n, "import java.")) &&
        (has_str(b, n, ";") || has_str(b, n, "public static void main"))) {
        return {"java", "text/x-java-source"};
    }
    // Go
    if (match(b, n, pos, "package ", 8) && (has_str(b, n, "func ") || has_str(b, n, "import \"") || has_str(b, n, "import ("))) {
        return {"go", "text/x-go"};
    }
    // Python
    if (has_str(b, n, "def ") && (has_str(b, n, "import ") || has_str(b, n, "from ") || has_str(b, n, "if __name__"))) {
        return {"py", "text/x-python"};
    }
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
    // INI / TOML 风格配置
    if (b[pos] == '[' && has_str(b, n, "]\n") && has_str(b, n, "=")) {
        return {"ini", "text/plain"};
    }

    return {"txt", "text/plain"};
}

} // namespace

FileType detect_bytes(const uint8_t* b, size_t n) {
    if (!b || n == 0) return {"empty", "inode/x-empty"};

    // 1. 图像格式 (PNG / JPG / GIF / WEBP / BMP / TIFF / ICO / PSD / JXL /JP2 / EXR / HDR / DDS / BPG)
    if (match(b, n, 0, "\x89PNG\r\n\x1a\n", 8)) return {"png", "image/png"};
    if (match(b, n, 0, "\xFF\xD8\xFF", 3)) return {"jpg", "image/jpeg"};
    if (match(b, n, 0, "GIF87a", 6) || match(b, n, 0, "GIF89a", 6)) return {"gif", "image/gif"};
    if (match(b, n, 0, "RIFF", 4) && match(b, n, 8, "WEBP", 4)) return {"webp", "image/webp"};
    if (match(b, n, 0, "BM", 2)) return {"bmp", "image/bmp"};
    if (match(b, n, 0, "II*\x00", 4) || match(b, n, 0, "MM\x00*", 4)) return {"tif", "image/tiff"};
    if (match(b, n, 0, "\x00\x00\x01\x00", 4)) return {"ico", "image/x-icon"};
    if (match(b, n, 0, "\x00\x00\x02\x00", 4)) return {"cur", "image/x-win-bitmap"};
    if (match(b, n, 0, "8BPS", 4)) return {"psd", "image/vnd.adobe.photoshop"};
    if (match(b, n, 0, "\xFF\x0A", 2) || match(b, n, 0, "\x00\x00\x00\x0CJXL \x0D\x0A\x87\x0A", 12)) return {"jxl", "image/jxl"};
    if (match(b, n, 0, "\x00\x00\x00\x0CjP  \r\n\x87\n", 12)) return {"jp2", "image/jp2"};
    if (match(b, n, 0, "\x76\x2F\x31\x01", 4)) return {"exr", "image/x-exr"};
    if (match(b, n, 0, "#?RADIANCE\n", 11) || match(b, n, 0, "#?RGBE\n", 7)) return {"hdr", "image/vnd.radiance"};
    if (match(b, n, 0, "DDS ", 4)) return {"dds", "image/vnd-ms.dds"};
    if (match(b, n, 0, "BPG\xFB", 4)) return {"bpg", "image/bpg"};

    // 2. 文档与 Office (PDF / RTF / OLE2 / ZIP-OOXML-ODF)
    if (match(b, n, 0, "%PDF-", 5)) return {"pdf", "application/pdf"};
    if (match(b, n, 0, "{\\rtf", 5)) return {"rtf", "application/rtf"};
    if (match(b, n, 0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8)) return classify_ole2(b, n);
    if (match(b, n, 0, "PK\x03\x04", 4) || match(b, n, 0, "PK\x05\x06", 4)) return classify_zip(b, n);

    // 3. 压缩包、归档与磁盘镜像 (RAR / 7Z / GZ / BZ2 / XZ / ZST / LZ4 / LZO / LZIP / CAB / DEB / RPM / CPIO / AR / TAR / DMG / QCOW2 / VMDK / VHD / VDI / SQUASHFS)
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
    if (match(b, n, 0, "!<arch>\ndebian", 14)) return {"deb", "application/vnd.debian.binary-package"};
    if (match(b, n, 0, "!<arch>\n", 8)) return {"a", "application/x-archive"};
    if (match(b, n, 0, "\xED\xAB\xEE\xDB", 4)) return {"rpm", "application/x-rpm"};
    if (match(b, n, 0, "070701", 6) || match(b, n, 0, "070702", 6) || match(b, n, 0, "070707", 6)) return {"cpio", "application/x-cpio"};
    if (match(b, n, 257, "ustar", 5)) return {"tar", "application/x-tar"};
    if (match(b, n, 0, "hsqs", 4)) return {"squashfs", "application/vnd.squashfs"};
    if (match(b, n, 0, "QFI\xFB", 4)) return {"qcow2", "application/x-qemu-disk"};
    if (match(b, n, 0, "KDMV", 4)) return {"vmdk", "application/x-vmdk-disk"};
    if (match(b, n, 0, "conectix", 8)) return {"vhd", "application/x-vhd-disk"};
    if (match(b, n, 0, "<<< Oracle VM VirtualBox Disk Image >>>", 39)) return {"vdi", "application/x-vdi-disk"};
    // ISO9660 光盘镜像特征位于偏移 0x8001 (32769) 字节处
    if (match(b, n, 0x8001, "CD001", 5) || match(b, n, 0x8801, "CD001", 5) || match(b, n, 0x9001, "CD001", 5)) {
        return {"iso", "application/x-iso9660-image"};
    }

    // 4. 字体 (TTF / OTF / WOFF / WOFF2)
    if (match(b, n, 0, "\x00\x01\x00\x00\x00", 5)) return {"ttf", "font/ttf"};
    if (match(b, n, 0, "OTTO", 4)) return {"otf", "font/otf"};
    if (match(b, n, 0, "wOFF", 4)) return {"woff", "font/woff"};
    if (match(b, n, 0, "wOF2", 4)) return {"woff2", "font/woff2"};

    // 5. 可执行文件与数据库 (ELF / EXE / Mach-O / Class / DEX / WASM / PYC / SQLite / PCAP)
    if (match(b, n, 0, "\x7F" "ELF", 4)) return {"elf", "application/x-executable"};
    if (match(b, n, 0, "MZ", 2)) return {"exe", "application/x-msdownload"};
    if (match(b, n, 0, "\xFE\xED\xFA\xCE", 4) || match(b, n, 0, "\xFE\xED\xFA\xCF", 4) ||
        match(b, n, 0, "\xCE\xFA\xED\xFE", 4) || match(b, n, 0, "\xCF\xFA\xED\xFE", 4)) return {"macho", "application/x-mach-binary"};
    if (match(b, n, 0, "\xCA\xFE\xBA\xBE", 4)) return {"class", "application/java-vm"};
    if (match(b, n, 0, "dex\n03", 6)) return {"dex", "application/vnd.android.dex"};
    if (match(b, n, 0, "\x00" "asm", 4)) return {"wasm", "application/wasm"};
    if (match(b, n, 0, "SQLite format 3\x00", 16)) return {"sqlite", "application/vnd.sqlite3"};
    if (match(b, n, 0, "\xD4\xC3\xB2\xA1", 4) || match(b, n, 0, "\xA1\xB2\xC3\xD4", 4)) return {"pcap", "application/vnd.tcpdump.pcap"};
    if (match(b, n, 0, "\x0A\x0D\x0D\x0A", 4)) return {"pcapng", "application/x-pcapng"};

    // 6. UTF-16 / UTF-32 BOM 文本（置于裸 MP3 帧同步检测前，避免 0xFF 0xFE 冲突）
    if (match(b, n, 0, "\xFF\xFE\x00\x00", 4) || match(b, n, 0, "\x00\x00\xFE\xFF", 4)) return {"txt", "text/plain; charset=utf-32"};
    if (match(b, n, 0, "\xFF\xFE", 2) || match(b, n, 0, "\xFE\xFF", 2)) return {"txt", "text/plain; charset=utf-16"};

    // 7. 音视频与 ISO BMFF 容器 (WAV / AVI / MP3 / FLAC / OGG / MIDI / FLV / MKV / MP4 / MOV / HEIC / AVIF)
    if (match(b, n, 0, "RIFF", 4) && match(b, n, 8, "WAVE", 4)) return {"wav", "audio/x-wav"};
    if (match(b, n, 0, "RIFF", 4) && match(b, n, 8, "AVI ", 4)) return {"avi", "video/x-msvideo"};
    if (match(b, n, 0, "ID3", 3) || (n >= 2 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0 && (b[1] & 0x18) != 0x08 && (b[1] & 0x06) != 0)) return {"mp3", "audio/mpeg"};
    if (match(b, n, 0, "fLaC", 4)) return {"flac", "audio/x-flac"};
    if (match(b, n, 0, "OggS", 4)) return {"ogg", "audio/ogg"};
    if (match(b, n, 0, "MThd", 4)) return {"mid", "audio/midi"};
    if (match(b, n, 0, "FLV\x01", 4)) return {"flv", "video/x-flv"};
    if (match(b, n, 0, "\x1A\x45\xDF\xA3", 4)) {
        if (has_str(b, n, "webm")) return {"webm", "video/webm"};
        return {"mkv", "video/x-matroska"};
    }
    if (match(b, n, 4, "ftyp", 4)) return classify_ftyp(b, n);

    // 8. UTF-8 (含或不含 BOM) / ASCII 启发式扫描与源码细分
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

    // A. ZIP 容器：若前 4KB 未命中特征，跳读末尾 64KB 中央目录
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

    // B. OLE2 旧版 Office 容器 (doc/xls/ppt/vsd/msg)：Directory Entry 常在文件后部，读取前 64KB + 后 64KB
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

    // C. 若前 4KB 未识别出格式：检查 0x8001 处的 ISO9660 光盘签名 "CD001"，以及末尾 512B 的 Apple DMG 签名 "koly"
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
