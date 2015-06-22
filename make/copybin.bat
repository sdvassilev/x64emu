@echo off
if "%1" == "__SPAWNED__" goto main
cmd.exe /c "%0" __SPAWNED__ %*
if ERRORLEVEL 1 echo ERRORLEVEL=%ERRORLEVEL%
goto end

:main

rem  copybin <file name pattern> <src dir pattern> <dest dir>

shift

if "%1" == "" (
@echo Parameter 1 should be a file name pattern
exit /b 0
)

if "%2" == "" (
@echo Parameter 2 should be a source dir patterh
exit /b 0
)

if "%3" == "" (
@echo Parameter 3 should be a dest dir
exit /b 0
)

for /R .\ %%f in (%1) do (
call :copyif %%f %2 %3
)

:end
exit /b 0

:copyif

@echo %1 | findstr /i %2 > tmpobj.txt
set srcFile=
set /p srcFile=<tmpobj.txt
if "%srcFile%" NEQ "" (
xcopy /Y /Q %srcFile% %3 > nul
) 
set srcFile=
del /Q tmpobj.txt 2> nul

rem End of copyif
exit /b 0