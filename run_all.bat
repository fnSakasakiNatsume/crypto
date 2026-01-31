@echo off
echo ========================================
echo TLS Handshake Demo - All Modules
echo ========================================
echo.

cd out

echo [1/4] Running Key Exchange Demo...
echo ========================================
java tls.demo.KeyExchangeDemo
echo.
echo Press any key to continue...
pause >nul
echo.

echo [2/4] Running Cipher Suite Demo...
echo ========================================
java tls.demo.CipherSuite
echo.
echo Press any key to continue...
pause >nul
echo.

echo [3/4] Running Signature Verification Demo...
echo ========================================
java tls.demo.SignatureVerify
echo.
echo Press any key to continue...
pause >nul
echo.

echo [4/4] Running Complete Handshake Simulator...
echo ========================================
java tls.demo.TLSHandshakeSimulator
echo.

pause
