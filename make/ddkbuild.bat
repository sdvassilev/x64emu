@echo off
rem //
rem // This script can build any project if it has proper sources file. The script can 
rem // build targets for WIN7 OS and for the x86 and x64/amd64 platforms. 
rem //
rem // PREREQUISITES:
rem	//		1. WIN7 ddk installed
rem	//		2. The "MSWDK" environment var needs to be set pointing to the 
rem //		   actual ddk install dir.
rem //
rem // USAGE: ddkbuild [debug|release|amd64dbg|amd64rel] [-a]
rem //
rem //
rem // LIMITATIONS: not certain where exactly to start
rem //

@echo off
if "%1" == "__SPAWNED__" goto main
cmd.exe /c "%0" __SPAWNED__ %*
if ERRORLEVEL 1 echo ERRORLEVEL=%ERRORLEVEL%
goto end

:main

shift

rem //
rem // Sanity checks
rem //

rem //
rem // Is MSWDK set and points to an existing location?
rem //

if "%MSWDK%" == "" (

@Echo Error: MSWDK is not set or points to a non-existing directory!
@Echo Please set MSWDK to point to the DDK directory!

exit /b 1
)

if not exist %MSWDK% (

@Echo Error: MSWDK points to a non-existing directory!
@Echo Please set MSWDK to point to the DDK directory!

exit /b 1
)

rem //
rem // Check whether the target root dir exists
rem //

if "%ROOTDIR%" == "" goto InvalidTargetRoot

if not exist "%ROOTDIR%" goto InvalidTargetRoot

rem //
rem // End sanity checks
rem //

rem //
rem // Parse the input arguments. We do not care about the ordering of args. 
rem // If no args are provided we'll build release target for win7 x64
rem //

set TARGETOS=WIN7
set TARGETCPU=x64
set BUILDCONFIG=fre
set REBUILD=
set CLEANME=
set WDK_TARGET=

set TARGET_BUILD_CONFIG=amd64rel
set WDK_TARGET_CPU=amd64
set WDK_TARGET_SUB_DIR=.\objfre_win7_%WDK_TARGET_CPU%

:ParseArgs

if "%1" == "" goto ParsArgsDone

if /I "%1" == "WIN7" (
set TARGETOS=WIN7

) else if /I "%1" == "debug" (
set TARGETCPU=i386
set BUILDCONFIG=chk
set TARGET_BUILD_CONFIG=debug
set WDK_TARGET_CPU = i386
set WDK_TARGET_SUB_DIR=objchk_win7_%WDK_TARGET_CPU%

) else if /I "%1" == "amd64dbg" (
set BUILDCONFIG=chk
set TARGETCPU=x64
set TARGET_BUILD_CONFIG=amd64dbg
set WDK_TARGET_CPU = amd64
set WDK_TARGET_SUB_DIR=objchk_win7_%WDK_TARGET_CPU%

) else if /I "%1" == "Release" (
set TARGETCPU=i386
set BUILDCONFIG=fre
set TARGET_BUILD_CONFIG=release
set WDK_TARGET_CPU = i386
set WDK_TARGET_SUB_DIR=objfre_win7_%WDK_TARGET_CPU%

) else if /I "%1" == "amd64rel" (
set BUILDCONFIG=fre
set TARGETCPU=x64
set TARGET_BUILD_CONFIG=amd64rel
set WDK_TARGET_CPU = amd64
set WDK_TARGET_SUB_DIR=objfre_win7_%WDK_TARGET_CPU%

) else  if /I "%1" == "-a" (
set REBUILD=1

) else if /I "%1" == "-clean" (
set CLEANME=1

) else (
goto Usage

)


shift

goto ParseArgs

:ParsArgsDone

set TARGET_DIR=%ROOTDIR%\%TARGET_BUILD_CONFIG%
if not exist "%TARGET_DIR%" (
md %TARGET_DIR%
)
pushd %TARGET_DIR%
set TARGET_DIR=%CD%
popd
@echo TARGET DIR=%TARGET_DIR%

set WDK_TARGET=%WDK_TARGET_SUB_DIR%\%WDK_TARGET_CPU%

@echo WDK_TARGET=%WDK_TARGET%


pushd .
call %MSWDK%\bin\setenv.bat %MSWDK% %BUILDCONFIG% %TARGETOS% %TARGETCPU% no_oacr
popd

if "%CLEANME%" == "1" (
build.exe /c
goto end
)

if "%REBUILD%" == "1" (
build.exe -cwD
goto end
) 

build.exe -wD
goto end


:InvalidTargetRoot

@Echo Please specify valid root target directory!

:Usage

@Echo.
@Echo Usage: "ddkbuild [OS] [config] [-a]"
@Echo.
@Echo where:
@Echo     "[OS]                = WIN7"
@echo     "[config]            = debug|release|amd64dbg|amd64rel
@Echo     "[-a]                = Rebuild all"
@Echo.
@Echo examples:
@Echo          ddkbuild
@Echo          ddkbuild release
@Echo          ddkbuild amd64fre
@Echo          ddkbuild debug -a
@Echo          ddkbuild amd64rel -a
@Echo.

exit /b 1

:end

call %ROOTDIR%\make\copybin.bat *.sys %WDK_TARGET% %TARGET_DIR%
call %ROOTDIR%\make\copybin.bat *.exe %WDK_TARGET% %TARGET_DIR%
call %ROOTDIR%\make\copybin.bat *.dll %WDK_TARGET% %TARGET_DIR%
call %ROOTDIR%\make\copybin.bat *.pdb %WDK_TARGET% %TARGET_DIR%
call %ROOTDIR%\make\copybin.bat *.lib %WDK_TARGET% %TARGET_DIR%

if exist "*.inf" (
xcopy /Y /Q *.inf %TARGET_DIR% 2 > nul
)

rem //
rem // Finally unset all the env vars
rem //

set TARGETOS=
set TARGETCPU=
set BUILDCONFIG=
set REBUILD=
set TARGET_DIR=
set TARGET_BUILD_CONFIG=
set WDK_TARGET_SUB_DIR=

exit /b 0