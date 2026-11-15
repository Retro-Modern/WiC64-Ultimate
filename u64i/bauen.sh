#!/bin/zsh
# WiC64 für den Ultimate 64 der ersten Generation (Nios II) bauen.
#
#   u64i/bauen.sh <arbeitsordner>
#
# Holt Gideons Firmware 3.15a (dddd29b2), legt den WiC64-Stand aus
# u64e2/native darüber, spielt u64i/patches/u64i.patch ein und baut ein
# RAM-Abbild WiC64_U64I_<FASSUNG>.u64 (über "Run Update" zu laden).
#
# Braucht: nios2-elf-Toolchain mit GCC 13 (werkzeug/nios2-toolchain.sh,
# Ziel ~/opt/nios2-elf-gcc13; anderer Ort über NIOS2_TOOLCHAIN), Python 3, git.
set -e
FASSUNG=${FASSUNG:-B5RM3}
HIER=${0:A:h}
REPO=${HIER:h}
ARBEIT=${1:?Arbeitsordner angeben}
TC=${NIOS2_TOOLCHAIN:-$HOME/opt/nios2-elf-gcc13}
J=${JOBS:-8}
export PATH=$TC/bin:$PATH
nios2-elf-gcc --version | head -1

mkdir -p $ARBEIT; ARBEIT=${ARBEIT:A}; G=$ARBEIT/gideon
# Gideons Makefiles rufen "python" auf; macOS kennt nur python3.
mkdir -p $ARBEIT/bin; ln -sf $(command -v python3) $ARBEIT/bin/python; printf '#!/bin/sh\necho wic64-bau\n' > $ARBEIT/bin/hostname; chmod +x $ARBEIT/bin/hostname  # nicht den eigenen Rechnernamen einbauen
export PATH=$ARBEIT/bin:$PATH
if [ ! -d $G ]; then
  git clone -q --filter=blob:none https://github.com/GideonZ/1541ultimate.git $G
  git -C $G checkout -q dddd29b2
  git -C $G submodule update -q --init software/httpd software/lwip
  rsync -a $REPO/u64e2/native/software/ $G/software/
  GC=(git -C $G -c user.name=WiC64 -c user.email=wic64@localhost)
  $GC add -A && $GC commit -qm "Gideon 3.15a + WiC64 u64e2/native"
  $GC apply --index $HIER/patches/u64i.patch
  $GC commit -qm "WiC64 U64-I $FASSUNG"
fi

cd $G
make -s -C tools >/dev/null
make -s -C software/nios_solo_bsp >/dev/null
make -s -C software/nios_appl_bsp >/dev/null
make -s -C target/libs/nios2/lwip AR=nios2-elf-ar >/dev/null
make -s -C software/6502/sidcrt TASS=$G/tools/64tass/64tass >/dev/null

# wolfSSL (TLS auf der Nios-CPU) aus u64e2/crypto
C=$ARBEIT/crypto-nios2
python3 $HIER/werkzeug/wolfssl_nios2.py $C $REPO/u64e2 $TC > $ARBEIT/wolfssl.txt
DIGEST=$(sed -n 2p $ARBEIT/wolfssl.txt)

cd target/u64/nios2/ultimate
mkdir -p output result
make -j$J AR=nios2-elf-ar WIC64_RAM=1 TASS=$G/tools/64tass/64tass \
  EFFORT="-DP08_SERVICE=1 -DP05_RAM_DIAGNOSTIC=1 -DP14_TLS=1" \
  P14_TLS_LIBRARY=$C/libwolfssl.a P14_WOLFSSL_DIR=$REPO/u64e2/crypto/wolfssl \
  P14_TLS_CONFIG=$REPO/u64e2/crypto P14_TLS_INPUT_SHA256=$DIGEST \
  P14_TLS_IDENTITY_HEADER=$C/build_identity.h > $ARBEIT/bau.log 2>&1 \
  || { tail -20 $ARBEIT/bau.log; exit 1; }

python3 $HIER/werkzeug/u64_abbild.py result/ultimate.elf result/ultimate.bin \
  $ARBEIT/WiC64_U64I_$FASSUNG.u64
