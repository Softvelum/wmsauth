@echo off

echo Installation on %PROCESSOR_ARCHITECTURE% platform
echo OS type is %OS%

set ASSEMBLY_NAME=authorize_plugin-2003.dll
 
IF %PROCESSOR_ARCHITECTURE% == x86 (
        set FRAMEWORK=Framework
	call x86x64\install.bat
) ELSE (
	set FRAMEWORK=Framework64
        call x86x64\install.bat
)