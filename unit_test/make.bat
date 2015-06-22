@echo off
if "%1" == "__SPAWNED__" goto main
cmd.exe /c "%0" __SPAWNED__ %*
if ERRORLEVEL 1 echo ERRORLEVEL=%ERRORLEVEL%
goto return

:main
set ROOTDIR=..
call %ROOTDIR%\make\ddkbuild.bat %*

:return
