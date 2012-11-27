@rem Script to build luapcap

@setlocal
@set MYCOMPILE=cl /nologo /MD /O2 /W3 /TC /c /D_CRT_SECURE_NO_DEPRECATE /D "WIN32" /I"..\wpdpack\Include" /I"..\lua\src" /I"..\wt-win-common" /D "LUA_BUILD_AS_DLL" 
@set MYLINK=link /nologo /DLL /LIBPATH:"..\wpdpack\Lib" /LIBPATH:"..\wt-win-common" /LIBPATH:"..\lua\src" /TLBID:1 /DLL "lua51.lib" "wpcap.lib" "wt-win-common.lib" "Packet.lib" "ws2_32.lib" "kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib" "shell32.lib" "ole32.lib" "oleaut32.lib" "uuid.lib" "odbc32.lib" "odbccp32.lib" 
@set MYMT=mt /nologo

if "%PLATFORM%"=="X64" (
	@set MACHINE=X64
) else (
	@set MACHINE=X86
)

del pcap.lib pcap.dll
%MYCOMPILE% /D "_WINDLL" *.c
%MYLINK%  /export:luaopen_pcap /out:pcap.dll /implib:pcap.lib /MACHINE:%MACHINE% *.obj
del /Q *.obj *.exp
