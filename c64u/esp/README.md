# ESP application

Use x86-64 Ubuntu 24.04 or Ubuntu 24.04 under WSL2, with Python 3.12,
`python3-venv` and Git installed.

```sh
./setup.sh
./build.sh --clean
```

Setup downloads ESP-IDF 5.3.1, the pinned ESP compilers, CMake, Ninja and Python
dependencies into `.deps/`. The SDK revision and submodules are checked;
tool archives are verified with SHA256. Internet access is needed for setup;
the first run can take several minutes.

`complete/` contains the WiC64 ESP application. `stock_1_11/` contains the stock
bridge application. Both include their required UART source files.

The build produces `build/custom_app.bin`, `build/C64U_ESP_COMPLETE_APP.ESP`,
`build/stock_app.bin` and `build/C64U_ESP_STOCK_1.11.ESP`. Each `.ESP` container
contains one application record for the existing factory partition at `0x10000`.
The build never flashes a device.

ESP-IDF generates build timestamps and an ELF hash. Rebuilding can therefore
change image checksums even when the program code is unchanged. The top-level
build incorporates the rebuilt application and its matching resource checksums.

Project license: see `LICENSE.txt` in each source tree. Downloaded dependencies
retain their own licenses. Certificate bundle attribution is in
`complete/software/u64ctrl/ca/`.
