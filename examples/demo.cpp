#include "ftype/ftype.hpp"
#include <iomanip>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "用法: " << argv[0] << " <文件路径1> [文件路径2 ...]\n";
        return 1;
    }

    std::cout << std::left << std::setw(36) << "FILE"
              << std::setw(10) << "EXT"
              << "MIME\n"
              << std::string(76, '-') << "\n";

    for (int i = 1; i < argc; ++i) {
        ftype::FileType ft = ftype::detect_file(argv[i]);
        std::cout << std::left << std::setw(36) << argv[i]
                  << std::setw(10) << ft.ext
                  << ft.mime << "\n";
    }
    return 0;
}
