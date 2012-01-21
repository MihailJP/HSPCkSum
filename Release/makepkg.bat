del /q hspcksum\common\*
rmdir hspcksum\common
del /q hspcksum\hsphelp\*
rmdir hspcksum\hsphelp
del /q hspcksum\sample\*
rmdir hspcksum\sample
del /q hspcksum\*
del /q hspcksum.zip
rmdir hspcksum

mkdir hspcksum
mkdir hspcksum\common
mkdir hspcksum\hsphelp
mkdir hspcksum\sample

copy hspcksum.dll hspcksum
copy common\* hspcksum\common
copy hsphelp\* hspcksum\hsphelp
copy sample\* hspcksum\sample
rem copy readme.txt hspcksum
"C:\Program Files\7-Zip\7z.exe" a -mx=9 hspcksum.zip hspcksum
