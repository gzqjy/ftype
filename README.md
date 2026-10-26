# ftype

基于 **C++11** 的零第三方依赖真实文件格式判定库。通过魔数签名（Magic Bytes）、容器内部目录跳读（ZIP / OLE2 / ISO9660 / DMG / ELF / PE）及 UTF-8 启发式语法扫描，忽略文件扩展名直接识别 **220+ 种真实格式**。

## 特性

- **零外部依赖**：仅使用 C++11 标准库，跨平台（Linux / Windows / macOS）开箱即用。
- **O(1) 极速跳读与容器深潜**：无需全量读取或解压大文件——
  - **ZIP 衍生包**：读取前 4KB + 末尾 64KB 中央目录，精准区分 `docx`/`xlsx`/`xlsb`/`pptx`/`vsdx`/`ofd`/`uof`/`eio`/`cebx`/`npz`/`apk`/`aab`/`jar`/`war`/`ear`/`xpi`/`msix`/`ipa`/`epub`/`odt`/`ods`/`odp`。
  - **OLE2 复合文档**：扫描 UTF-16LE 目录流名称，区分微软 Office（`doc`/`xls`/`ppt`/`vsd`/`msg`）、金山 WPS（`wps`/`et`/`dps`）与永中 Office（`eio`）。
  - **ELF / PE 结构体细分**：解析 ELF `e_type` 与 `PT_INTERP` 区分 `elf`（可执行）、`so`（共享库）、`o`（目标文件）、`core`（核心转储）与 `appimage`；解析 PE `Characteristics` 与 `Subsystem` 区分 `exe`、`dll` 与 `sys`（驱动）。
  - **大偏移镜像與流同步**：自动跳读 `0x8001` 扇区识别 `iso` 光盘镜像，跳读末尾 512 字节识别苹果 `dmg`，按 188/192 字节帧同步区分 `.ts`/`.m2ts` 视频流与 `.ts` TypeScript 源码。
- **文本与代码启发式识别**：自动校验 UTF-8 多字节序列（含 4KB 截断边界容错），细分 **40+ 种**编程语言、构建脚本、数据交换与配置文件。

## 目录结构

```text
.
├── CMakeLists.txt
├── include/ftype/ftype.hpp   # 对外头文件
├── src/ftype.cpp             # 核心识别实现
├── examples/demo.cpp         # 命令行检测工具
├── tests/test_ftype.cpp      # 单元测试 (249 项断言)
└── test_samples/             # 225 个真实测试样本文件
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

## 支持格式一览（220+ 种）

| 类别 | 支持的扩展名 (`ext`) |
|------|----------------------|
| **国产办公 / 文献 / 版式** | `ofd` (GB/T 33190)、`uof` (GB/T 20916)、`wps`、`et`、`dps` (金山 WPS)、`eio` (永中 Office)、`caj`、`kdh` (中国知网)、`ceb`、`cebx` (方正阿帕比) |
| **微软 Office / 电子书 / 帮助** | `docx`、`xlsx`、`xlsb`、`pptx`、`vsdx`、`doc`、`xls`、`ppt`、`vsd`、`msg`、`odt`、`ods`、`odp`、`pdf`、`rtf`、`csv`、`tsv`、`epub`、`mobi`、`fb2`、`djvu`、`indd`、`ps`、`eps`、`chm`、`hlp` |
| **图像与相机 RAW 原片** | `png`、`jpg`、`gif`、`webp`、`bmp`、`tif`、`ico`、`cur`、`svg`、`heic`、`avif`、`cr2`、`cr3` (佳能)、`orf` (奥林巴斯)、`rw2` (松下)、`raf` (富士)、`psd`、`psb`、`jxl`、`jp2`、`exr`、`hdr`、`dds`、`bpg` |
| **CAD / 3D 模型 / 地理天文** | `dwg`、`dxf`、`glb`、`gltf`、`blend`、`fbx`、`stl`、`obj`、`3ds`、`shp`、`fits` |
| **大数据 / AI / 科学数据** | `parquet`、`orc`、`avro`、`arrow`、`feather`、`h5` (HDF5)、`nc` (NetCDF)、`npy`、`npz` (NumPy)、`gguf` (LLM 权重) |
| **数据库与搜索索引** | `sqlite`、`mdf` (SQL Server)、`mdb`、`accdb` (Access)、`rdb` (Redis)、`cfs` (Lucene)、`pst`、`kdbx` (KeePass) |
| **压缩包 / 归档 / 扩展包** | `zip`、`rar`、`7z`、`gz`、`bz2`、`xz`、`zst`、`lz4`、`lzo`、`lz`、`Z`、`tar`、`cab`、`wim`、`xar`、`crx`、`xpi`、`deb`、`rpm`、`cpio`、`a`、`apk`、`aab`、`jar`、`war`、`ear`、`ipa`、`msix`、`msi` |
| **光盘与虚拟机磁盘** | `iso`、`dmg`、`qcow2`、`vmdk`、`vhd`、`vhdx`、`vdi`、`squashfs`、`vmx`、`vbox`、`ovf`、`swp` |
| **音视频与字幕** | `mp4`、`m4v`、`mkv`、`webm`、`mov`、`avi`、`wmv`、`mpg`、`ts` (MPEG-TS)、`m2ts`、`mxf`、`flv`、`3gp`、`ogv`、`mp3`、`aac`、`wav`、`aiff`、`flac`、`ape`、`wv`、`dsf`、`dff`、`ogg`、`opus`、`m4a`、`amr`、`mid`、`srt`、`vtt` |
| **可执行 / 库 / 目标 / 调试** | `elf`、`so` (共享库)、`o` (目标文件)、`core` (核心转储)、`appimage`、`exe`、`dll` (动态库)、`sys` (驱动)、`pdb`、`macho`、`class`、`dex`、`pyc`、`wasm`、`hex`、`lnk`、`dmp`、`evtx`、`reg`、`hiv`、`ab`、`plist`、`pcap`、`pcapng` |
| **安全证书 / 密钥 / 邮件日历** | `pem`、`der`、`key`、`asc` (PGP)、`pub` (SSH)、`eml`、`mbox`、`ics`、`vcf` |
| **字体** | `ttf`、`otf`、`woff`、`woff2` |
| **编程语言与配置** | `c`、`cpp`、`cs`、`java`、`kt`、`rs`、`go`、`py`、`js`、`ts` (TypeScript)、`html`、`css`、`php`、`rb`、`swift`、`m` (Obj-C)、`lua`、`sh`、`ps1`、`bat`、`asm`、`wat`、`sql`、`proto`、`ui`、`qrc`、`qml`、`cu` (CUDA)、`json`、`jsonl`、`xml`、`yaml`、`toml`、`ini`、`env`、`har`、`rss`、`atom`、`webmanifest`、`graphql`、`md`、`txt` |
