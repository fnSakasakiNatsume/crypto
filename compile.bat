@echo off
echo ========================================
echo TLS Handshake Demo - Compilation
echo ========================================
echo.

echo Creating output directory...
if not exist "out" mkdir out

echo Compiling Java files...
javac -d out -encoding UTF-8 *.java

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Compilation successful!
    echo ========================================
    echo.
    echo To run the demo:
    echo   run.bat
) else (
    echo.
    echo ========================================
    echo Compilation failed!
    echo ========================================
)

pause
