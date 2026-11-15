#!/bin/zsh
# nios2-elf-Toolchain (binutils 2.42, GCC 13.3, newlib 4.4) fuer macOS arm64.
# Ziel: ~/opt/nios2-elf-gcc13. Fuer die WiC64-Portierung auf den ersten U64.
set -e
P=$HOME/opt/nios2-elf-gcc13
W=$HOME/opt/nios2-bau
B=$(brew --prefix)
J=16
cd $W
[ -f binutils-2.42.tar.xz ] || curl -sLO https://ftp.gnu.org/gnu/binutils/binutils-2.42.tar.xz
[ -f gcc-13.3.0.tar.xz ]    || curl -sLO https://ftp.gnu.org/gnu/gcc/gcc-13.3.0/gcc-13.3.0.tar.xz
[ -f newlib-4.4.0.20231231.tar.gz ] || curl -sLO https://sourceware.org/pub/newlib/newlib-4.4.0.20231231.tar.gz
[ -d binutils-2.42 ] || tar xf binutils-2.42.tar.xz
[ -d gcc-13.3.0 ]    || tar xf gcc-13.3.0.tar.xz
[ -d newlib-4.4.0.20231231 ] || tar xf newlib-4.4.0.20231231.tar.gz
export PATH=$P/bin:$PATH

echo "== binutils"; rm -rf b-binutils; mkdir b-binutils; cd b-binutils
../binutils-2.42/configure --target=nios2-elf --prefix=$P --disable-nls --disable-werror --disable-gdb --disable-sim --with-system-zlib >/dev/null
make -j$J >/dev/null; make install >/dev/null; cd ..

echo "== gcc stufe 1"; rm -rf b-gcc1; mkdir b-gcc1; cd b-gcc1
../gcc-13.3.0/configure --target=nios2-elf --prefix=$P --disable-nls --enable-languages=c \
  --without-headers --with-newlib --disable-shared --disable-threads --disable-libssp \
  --with-system-zlib --with-gmp=$B --with-mpfr=$B --with-mpc=$B --with-isl=$B >/dev/null
make -j$J all-gcc all-target-libgcc >/dev/null; make install-gcc install-target-libgcc >/dev/null; cd ..

echo "== newlib"; rm -rf b-newlib; mkdir b-newlib; cd b-newlib
../newlib-4.4.0.20231231/configure --target=nios2-elf --prefix=$P --disable-nls >/dev/null
make -j$J >/dev/null; make install >/dev/null; cd ..

echo "== gcc stufe 2 (C, C++)"; rm -rf b-gcc2; mkdir b-gcc2; cd b-gcc2
../gcc-13.3.0/configure --target=nios2-elf --prefix=$P --disable-nls --enable-languages=c,c++ \
  --with-newlib --disable-shared --disable-threads --disable-libssp --disable-libstdcxx-pch \
  --with-system-zlib --with-gmp=$B --with-mpfr=$B --with-mpc=$B --with-isl=$B >/dev/null
make -j$J >/dev/null; make install >/dev/null; cd ..

echo "== fertig"; $P/bin/nios2-elf-gcc --version | head -1
