@echo off
echo ========================================
echo TLS Server - 服务器端
echo ========================================
echo.
echo 注意：服务器将监听在端口 8888
echo 等待客户端连接...
echo.

cd out
java tls.demo.TLSServer

echo.
pause
