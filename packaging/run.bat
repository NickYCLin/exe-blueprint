@echo off
rem ExeBlueprint 雙擊／拖放啟動器。
rem 直接雙擊會出現提示；也可以把 EXE／DLL／資料夾／ZIP 拖到這個檔案上分析。
setlocal enabledelayedexpansion
chcp 65001 >nul
cd /d "%~dp0"

set "EXE=exe-blueprint.exe"
if not exist "%EXE%" (
    echo 找不到 %EXE%，請確認它和這個 run.bat 放在同一個資料夾。
    echo.
    pause
    exit /b 1
)

if not "%~1"=="" (
    echo 正在分析：%~1
    "%EXE%" analyze "%~1"
    echo.
    echo 分析完成。輸出在上面顯示的資料夾裡。
    pause
    exit /b
)

echo ============================================================
echo  ExeBlueprint - Windows 應用程式分析工具（命令列）
echo ============================================================
echo.
echo  用法一：把要分析的 EXE / DLL / 資料夾 / ZIP 拖到 run.bat 上。
echo  用法二：在下面直接貼上路徑後按 Enter。
echo.
set /p "TARGET=要分析的路徑（留空按 Enter 只看說明）: "
echo.
if "%TARGET%"=="" (
    "%EXE%" --help
) else (
    "%EXE%" analyze "%TARGET%"
)
echo.
pause
