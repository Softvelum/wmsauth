@echo off
copy "%ASSEMBLY_NAME%" "C:\WINDOWS\system32\windows media\server\authorize_plugin.dll"
"C:\WINDOWS\Microsoft.NET\%FRAMEWORK%\v2.0.50727\regasm" "C:\WINDOWS\system32\windows media\server\authorize_plugin.dll" /tlb
REM net start wmserver
