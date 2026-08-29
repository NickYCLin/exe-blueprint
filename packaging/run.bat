@echo off
rem ExeBlueprint launcher. Double-click to get a prompt, or drag an
rem EXE / DLL / folder / ZIP / ASAR onto this file to analyze it.
rem (Kept ASCII-only so it works on every Windows locale. Chinese help is in README.txt.)
setlocal
pushd "%~dp0"
set "EXE=%~dp0exe-blueprint.exe"

if not exist "%EXE%" (
    echo Cannot find exe-blueprint.exe next to this run.bat. Extract the whole zip first.
    echo.
    pause
    popd
    exit /b 1
)

if not "%~1"=="" (
    echo Analyzing: %~1
    echo.
    "%EXE%" analyze "%~1"
    echo.
    echo Done. The output folder is shown above.
    pause
    popd
    exit /b
)

echo ============================================================
echo   ExeBlueprint - Windows app analyzer ^(command-line tool^)
echo ============================================================
echo.
echo   Option 1: drag an EXE / DLL / folder / ZIP / ASAR onto run.bat
echo   Option 2: paste a path below and press Enter
echo.
echo   Full instructions (Chinese) are in README.txt.
echo.
set /p "TARGET=Path to analyze (leave blank for --help): "
echo.
if "%TARGET%"=="" (
    "%EXE%" --help
) else (
    "%EXE%" analyze "%TARGET%"
)
echo.
pause
popd
