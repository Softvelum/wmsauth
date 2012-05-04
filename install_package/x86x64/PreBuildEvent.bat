@echo off
net stop wmserver /y
C:\WINDOWS\Microsoft.NET\%FRAMEWORK%\v2.0.50727\regasm /unregister "C:\WINDOWS\system32\windows media\server\authorize_plugin.dll"
del "C:\WINDOWS\system32\windows media\server\authorize_plugin.dll"
del "C:\WINDOWS\system32\windows media\server\authorize_plugin.tlb"
if errorlevel 1 goto CSharpReportError
goto CSharpEnd
:CSharpReportError
echo Project error: A tool returned an error code from the build event
exit 1
:CSharpEnd