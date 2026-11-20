#!/bin/zsh
# C64-Kern des MiSTer mit WiC64-Bruecke bauen.
#
#   mister/bauen.sh <arbeitsordner> [ordner-auf-dem-gaming-pc]
#
# Holt C64_MiSTer bei KERN (MiSTer-devel), spielt patches/c64-wic64.patch
# ein, legt rtl/wic64_bridge.sv dazu und baut auf dem Gaming-PC mit
# Quartus Lite 17.0 (ssh gamingpc). Ergebnis: <arbeitsordner>/C64_WIC64.rbf
set -e
KERN=${KERN:-88354ba}
HIER=${0:A:h}
ARBEIT=${1:?Arbeitsordner angeben}
ZIEL=${2:-c64wic}
mkdir -p $ARBEIT; ARBEIT=${ARBEIT:A}; K=$ARBEIT/C64_MiSTer
if [ ! -d $K ]; then
  git clone -q https://github.com/MiSTer-devel/C64_MiSTer.git $K
fi
git -C $K checkout -q -f $KERN
git -C $K clean -qfd
git -C $K apply $HIER/patches/c64-wic64.patch
cp $HIER/rtl/wic64_bridge.sv $K/rtl/
rm -f $ARBEIT/kern.zip
(cd $K && zip -qr $ARBEIT/kern.zip . -x 'releases/*' -x '.git/*')
sed "s/@ZIEL@/$ZIEL/g" $HIER/bau.ps1 > $ARBEIT/bau.ps1
ssh gamingpc "New-Item -ItemType Directory -Force C:\\mister\\$ZIEL | Out-Null"
scp -q $ARBEIT/kern.zip $ARBEIT/bau.ps1 gamingpc:C:/mister/$ZIEL/
ssh gamingpc "cd C:\\mister\\$ZIEL; tar -xf kern.zip; Remove-Item kern.zip;
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='powershell -NoProfile -ExecutionPolicy Bypass -File C:\\mister\\$ZIEL\\bau.ps1'} | Out-Null"
echo "Bau laeuft (rund 18 min). Stand: ssh gamingpc 'Get-Content C:\\mister\\$ZIEL\\stufen.txt'"
echo "Danach: scp gamingpc:C:/mister/$ZIEL/output_files/C64.rbf $ARBEIT/C64_WIC64.rbf"
