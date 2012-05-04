@echo off

echo Installation on %PROCESSOR_ARCHITECTURE% platform
echo OS type is %OS%
 
IF %PROCESSOR_ARCHITECTURE% == x86 (
        set FRAMEWORK=Framework
	call x86x64\uninstall.bat
) ELSE (
	set FRAMEWORK=Framework64
        call x86x64\uninstall.bat
)