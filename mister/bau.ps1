# C64-Kern mit WiC64-Bruecke: Synthese, Fit, Asm, Timing einzeln; Stufen nach stufen.txt
Set-Location C:\mister\@ZIEL@
$q = "C:\intelFPGA_lite\17.0\quartus\bin64"
"start $(Get-Date -Format HH:mm:ss)" | Out-File stufen.txt
& "$q\quartus_sh.exe" -t sys\build_id.tcl compile C64 C64 *> buildid.log
& "$q\quartus_map.exe" C64 *> map.log
"map $LASTEXITCODE $(Get-Date -Format HH:mm:ss)" | Out-File -Append stufen.txt
if ($LASTEXITCODE -ne 0) { exit 1 }
& "$q\quartus_fit.exe" C64 --parallel=1 *> fit.log
"fit $LASTEXITCODE $(Get-Date -Format HH:mm:ss)" | Out-File -Append stufen.txt
if ($LASTEXITCODE -ne 0) { exit 1 }
& "$q\quartus_asm.exe" C64 *> asm.log
"asm $LASTEXITCODE $(Get-Date -Format HH:mm:ss)" | Out-File -Append stufen.txt
& "$q\quartus_sta.exe" C64 --parallel=1 *> sta.log
"sta $LASTEXITCODE $(Get-Date -Format HH:mm:ss)" | Out-File -Append stufen.txt
