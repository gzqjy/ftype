# ftype

基于 **C++11** 的零第三方依赖真实文件格式判定库。通过魔数签名（Magic Bytes）、容器内部目录跳读（ZIP / OLE2 / ISO9660 / DMG / ELF / PE / SSTable）及 UTF-8 启发式语法扫描，忽略文件扩展名直接识别 **260+ 种真实格式**。

## 特性

- **零外部依赖**：仅使用 C++11 标准库，跨平台（Linux / Windows / macOS）开箱即用。
- **O(1) 极速跳读与容器深潜**：无需全量读取或解压大文件——
  - **ZIP 衍生包**：读取前 4KB + 末尾 64KB 中央目录，精准区分 `docx`/`docm`/`dotx`/`xlsx`/`xlsm`/`xltx`/`xlsb`/`pptx`/`pptm`/`ppsx`/`potx`/`vsdx`/`ofd`/`uof`/`eio`/`cebx`/`npz`/`apk`/`aab`/`jar`/`war`/`ear`/`xpi`/`msix`/`ipa`/`epub`/`odt`/`ott`/`ods`/`ots`/`odp`/`otp`。
  - **OLE2 复合文档**：扫描 UTF-16LE 目录流名称，区分微软 Office（`doc`/`xls`/`ppt`/`vsd`/`msg`）、金山 WPS（`wps`/`wpt`/`et`/`dps`）与永中 Office（`eio`）。
  - **ELF / PE / NE 结构体细分**：解析 ELF `e_type`、`PT_INTERP` 与 `.modinfo` 区分 `elf`（可执行）、`so`（共享库）、`o`（目标文件）、`ko`（Linux 内核模块）、`core`（核心转储）与 `appimage`；解析 PE/NE 区分 `exe`、`dll`、`sys`（驱动）与 `fon`（Windows 字体）。
  - **大偏移镜像与尾部魔数**：自动跳读 `0x8001` 扇区识别 `iso` 光盘镜像，跳读 4086 偏移识别 Linux `swap` 交换镜像，跳读末尾 512 字节识别苹果 `dmg`，跳读末尾 8 字节识别 RocksDB/LevelDB `sst`，按 188/192 字节帧同步区分 `.ts`/`.m2ts` 视频流与 `.ts` TypeScript 源码。
- **文本与代码启发式识别**：自动校验 UTF-8 多字节序列（含 4KB 截断边界容错），细分 **45+ 种**编程语言、构建脚本、数据交换与配置文件。

## 目录结构

```text
.
├── CMakeLists.txt
├── include/ftype/ftype.hpp   # 对外头文件
├── src/ftype.cpp             # 核心识别实现
├── examples/demo.cpp         # 命令行检测工具
├── tests/test_ftype.cpp      # 单元测试 (288 项断言)
└── test_samples/             # 264 个真实测试样本文件
```

## 快速开始

### 1. 编译与测试

```bash
cmake -B build && cmake --build build
ctest --test-dir build -V
```

### 2. 命令行 Demo

```bash
./build/ftype_demo test_samples/disguised_* test_samples/sample.ofd test_samples/sample.wps
```

输出示例：
```text
FILE                                EXT       MIME
----------------------------------------------------------------------------
test_samples/disguised_docx_as.pdf  docx      application/vnd.openxmlformats-officedocument.wordprocessingml.document
test_samples/disguised_png_as.txt   png       image/png
test_samples/sample.ofd             ofd       application/ofd
test_samples/sample.wps             wps       application/vnd.ms-works
```

### 3. C++ API 调用

```cpp
#include "ftype/ftype.hpp"
#include <iostream>

int main() {
    // 1. 按文件路径检测
    ftype::FileType ft = ftype::detect_file("sample.ofd");
    std::cout << ft.ext << " (" << ft.mime << ")\n"; // ofd (application/ofd)

    // 2. 按内存缓冲区检测
    const uint8_t buf[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    ftype::FileType mem_ft = ftype::detect_bytes(buf, sizeof(buf));
    std::cout << mem_ft.ext << "\n"; // png
}
```

---

## 一、已支持格式一览（260+ 种）

| 类别 | 已支持的扩展名 (`ext`) |
|------|----------------------|
| **1. 文本文档、办公与电子书** | `txt`、`md`、`doc`、`docx`、`docm`、`dotx`、`wps`、`wpt`、`odt`、`ott`、`xls`、`xlsx`、`xlsm`、`xlsb`、`xltx`、`et`、`csv`、`tsv`、`ods`、`ots`、`ppt`、`pptx`、`pptm`、`ppsx`、`potx`、`dps`、`odp`、`otp`、`vsd`、`vsdx`、`pdf`、`ofd` (GB/T 33190)、`uof` (GB/T 20916)、`eio` (永中)、`caj`、`kdh` (知网)、`ceb`、`cebx` (方正)、`rtf`、`epub`、`mobi`、`azw`、`azw3`、`fb2`、`djvu`、`indd`、`ps`、`eps`、`chm`、`hlp` |
| **2. 图片、相机 RAW、CAD 与 3D** | `jpg`、`png`、`gif`、`webp`、`bmp`、`tif`、`svg`、`ico`、`cur`、`heic`、`avif`、`dng`、`cr2`、`cr3` (佳能)、`nef` (尼康)、`arw` (索尼)、`orf` (奥林巴斯)、`rw2` (松下)、`raf` (富士)、`psd`、`psb`、`ai` (Illustrator)、`jxl`、`jp2`、`exr`、`hdr`、`dds`、`bpg`、`dwg`、`dxf`、`obj`、`stl`、`fbx`、`gltf`、`glb`、`3ds`、`blend`、`shp` |
| **3. 音频文件** | `mp3`、`wav`、`flac`、`aac`、`m4a`、`ogg`、`opus`、`wma`、`aiff`、`mid`、`amr`、`ape`、`wv` (WavPack)、`dsf`、`dff` |
| **4. 视频与字幕** | `mp4`、`m4v`、`mkv`、`avi`、`mpg`、`mov`、`webm`、`wmv`、`flv`、`ts` (MPEG-TS)、`m2ts`、`3gp`、`3g2`、`vob`、`mxf`、`ogv`、`srt`、`vtt` |
| **5. 压缩包与归档** | `zip`、`7z`、`rar`、`tar`、`gz`、`bz2`、`xz`、`zst`、`lz4`、`lzo`、`lz`、`Z`、`cab`、`iso`、`wim`、`xar`、`deb`、`rpm`、`cpio`、`a`、`jar`、`war`、`ear`、`apk`、`aab`、`ipa`、`crx`、`xpi`、`msix`、`msi` |
| **6. 编程语言与源代码** | `c`、`cpp`、`cs`、`java`、`class`、`kt`、`rs`、`go`、`py`、`pyc`、`js`、`ts` (TypeScript)、`tsx`、`html`、`css`、`scss`、`php`、`rb`、`swift`、`m` (Obj-C)、`lua`、`sh`、`ps1`、`bat`、`asm`、`wasm`、`wat`、`sql`、`proto`、`ui`、`qrc`、`qml`、`cu` (CUDA)、`pl` |
| **7. 配置、数据交换与科学数据** | `json`、`jsonl`、`bson`、`xml`、`yaml`、`toml`、`ini`、`properties`、`env`、`http`、`har`、`rss`、`atom`、`webmanifest`、`graphql`、`parquet`、`orc`、`avro`、`arrow`、`feather`、`h5` (HDF5)、`nc` (NetCDF)、`fits`、`npy`、`npz`、`gguf` |
| **8. 数据库与搜索索引** | `sqlite`、`mdf` (SQL Server)、`mdb`、`accdb` (Access)、`dbf` (dBASE/FoxPro)、`sst` (RocksDB/LevelDB)、`db` (Berkeley DB)、`lmdb`、`rdb` (Redis)、`cfs` (Lucene)、`pst`、`kdbx` |
| **9. 可执行、库、目标与调试** | `exe`、`dll`、`sys`、`elf`、`so`、`o`、`ko` (内核模块)、`core`、`appimage`、`macho`、`dex`、`coff` (Windows `.obj`)、`pdb`、`hex` (Intel HEX) |
| **10. 磁盘镜像、虚拟机与系统** | `iso`、`dmg`、`vdi`、`vmdk`、`vhd`、`vhdx`、`qcow2`、`squashfs`、`vmx`、`vbox`、`ovf`、`ova`、`dmp`、`swp` (Vim)、`swap` (Linux 交换分区) |
| **11. 证书、密钥与加密** | `der`、`pem`、`p7b` (PKCS#7)、`p8` (PKCS#8)、`p12` (PKCS#12)、`key`、`asc`、`gpg` (OpenPGP)、`pub` |
| **12. 字体、邮件、日历与其他** | `ttf`、`otf`、`woff`、`woff2`、`fon`、`eml`、`msg`、`mbox`、`pst`、`ics`、`vcf`、`lnk`、`reg`、`hiv`、`evtx`、`ab`、`plist`、`pcap`、`pcapng` |

---

## 二、不支持或受限的格式说明（原理性限制）

以下格式受限于**标准规范设计**（无魔数、强随机化、无结构裸流或目录包），无法仅凭文件内容直接独立判定：

### 1. 无魔数压缩 / 序列化位流
- **涉及后缀**：`.br` (Brotli)、`.pb` / `.protobuf` (二进制数据)、`.msgpack` / `.mpk`
- **限制原因**：标准规范故意省略固定文件头魔数。Brotli、Protobuf Wire Format 与 MessagePack 首字节直接是变长位流或字段 Tag，不存在全局特征签名，任意二进制流均可能产生碰撞。

### 2. 强加密隐写容器
- **涉及后缀**：`.hc` (VeraCrypt / TrueCrypt 等)
- **限制原因**：安全设计要求防探测。VeraCrypt 等规范要求整个容器（含文件头）100% 填充密码学伪随机字节，在数学特征上与纯随机白噪声完全一致。

### 3. 无固定结构的原始镜像与通用数据
- **涉及后缀**：`.img`、`.raw` (裸扇区镜像/无头相机 RAW)、`.bin`、`.rom`、`.dat`、`.sav`、`.idx`、`.tmp`、`.bak`
- **限制原因**：代表“任意二进制数据”或“磁盘裸扇区转储”，内容取决于特定程序或分区格式，无统一规范头，统一返回 `unknown (application/octet-stream)`。

### 4. 文件系统目录伪装包
- **涉及后缀**：`.app` (macOS 应用程序)、`.dSYM` (macOS 调试符号包)
- **限制原因**：本质是文件系统中的**文件夹（Directory）**而非单个文件。其内部包含 `Contents/MacOS/` 下的 `macho` 二进制文件与 `Info.plist`，应按目录遍历检测其内部可执行文件。

### 5. 双层复合归档
- **涉及后缀**：`.tar.gz` (`.tgz`)、`.tar.bz2` (`.tbz2`)、`.tar.xz` (`.txz`)、`.tar.zst`、`.svgz`
- **限制原因**：属于双层嵌套封装。本库为零依赖设计，不集成解压引擎，因此判定最外层压缩格式（返回 `gz` / `bz2` / `xz` / `zst`）；解压后再调用即可精准识别内层 `tar` 或 `svg`。

### 6. 完全同构的扩展名别名（直接归并至主格式）
同一格式标准的常见别名，底层字节结构 100% 相同，统一归并识别为主扩展名：
- **图像**：`.jpeg` / `.jpe` → `jpg`；`.tiff` → `tif`；`.dib` → `bmp`；`.heif` → `heic`
- **音视频**：`.oga` → `ogg`；`.aif` → `aiff`；`.midi` → `mid`；`.mpeg` → `mpg`
- **配置与数据**：`.yml` → `yaml`；`.ndjson` → `jsonl`；`.sqlite3` → `sqlite`
- **证书与密钥**：`.cer` / `.crt` → `der` 或 `pem`；`.pfx` → `p12`；`.pgp` → `gpg`
- **系统与库**：`.ical` → `ics`；`.appx` → `msix`；`.cpl` / `.pyd` → `dll`；`.lib` → `a`
