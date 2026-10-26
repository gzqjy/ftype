# ftype

基于 **C++11** 的零第三方依赖真实文件格式判定库。通过魔数签名（Magic Bytes）、容器内部目录跳读（ZIP / OLE2 / ISO9660 / DMG）及 UTF-8 启发式语法扫描，忽略文件扩展名直接识别 **95+ 种真实格式**。

## 特性

- **零外部依赖**：仅使用 C++11 标准库，跨平台（Linux / Windows / macOS）开箱即用。
- **O(1) 极速跳读**：无需全量读取或解压大文件——
  - **ZIP 衍生包**：读取前 4KB + 末尾 64KB 中央目录，精准区分 `docx`/`xlsx`/`pptx`/`ofd`/`uof`/`eio`/`apk`/`jar`/`ipa`/`epub`/`odt`/`odp`。
  - **OLE2 复合文档**：扫描 UTF-16LE 目录流名称，区分微软 Office（`doc`/`xls`/`ppt`/`vsd`/`msg`）、金山 WPS（`wps`/`et`/`dps`）与永中 Office（`eio`）。
  - **大偏移镜像**：自动跳读 `0x8001` 扇区识别 `iso` 光盘镜像，跳读末尾 512 字节识别苹果 `dmg`。
- **文本与代码启发式识别**：自动校验 UTF-8 多字节序列（含 4KB 截断边界容错），细分 19 种编程语言与配置文件。

## 目录结构

```text
.
├── CMakeLists.txt
├── include/ftype/ftype.hpp   # 对外头文件
├── src/ftype.cpp             # 核心识别实现
├── examples/demo.cpp         # 命令行检测工具
├── tests/test_ftype.cpp      # 单元测试 (122 项断言)
└── test_samples/             # 90+ 真实测试样本文件
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

## 支持格式一览（95+ 种）

| 类别 | 支持的扩展名 (`ext`) |
|------|----------------------|
| **国产办公 / 开放版式** | `ofd` (GB/T 33190)、`uof` (GB/T 20916)、`wps`、`et`、`dps` (金山 WPS)、`eio` (永中 Office) |
| **微软 Office / 文档** | `docx`、`xlsx`、`pptx`、`vsdx`、`doc`、`xls`、`ppt`、`vsd`、`msg`、`odt`、`ods`、`odp`、`pdf`、`rtf`、`epub` |
| **图像（传统 + 现代）** | `png`、`jpg`、`gif`、`webp`、`bmp`、`tif`、`ico`、`cur`、`svg`、`heic`、`avif`、`cr3`、`psd`、`jxl`、`jp2`、`exr`、`hdr`、`dds`、`bpg` |
| **压缩包与软件包** | `zip`、`rar`、`7z`、`gz`、`bz2`、`xz`、`zst`、`lz4`、`lzo`、`lz`、`Z`、`tar`、`cab`、`deb`、`rpm`、`cpio`、`a`、`apk`、`jar`、`ipa`、`msi` |
| **光盘与虚拟磁盘镜像** | `iso`、`dmg`、`qcow2`、`vmdk`、`vhd`、`vdi`、`squashfs` |
| **音视频** | `mp4`、`mkv`、`webm`、`mov`、`avi`、`flv`、`3gp`、`mp3`、`wav`、`flac`、`ogg`、`m4a`、`mid` |
| **可执行 / 数据库 / 抓包** | `elf`、`exe`、`macho`、`class`、`dex`、`wasm`、`sqlite`、`pcap`、`pcapng` |
| **字体** | `ttf`、`otf`、`woff`、`woff2` |
| **编程语言与配置** | `c`、`cpp`、`py`、`rs`、`go`、`java`、`js`、`ts`、`php`、`rb`、`pl`、`lua`、`sh`、`sql`、`json`、`xml`、`html`、`css`、`yaml`、`md`、`ini`、`txt` |
