@echo off
echo ========================================
echo TLS Client - 客户端
echo ========================================
echo.
echo 注意：将连接到 localhost:8888
echo 如需连接到其他服务器，请修改 TLSClient.java 中的 SERVER_HOST
echo.

cd out
java tls.demo.TLSClient

echo.
pause
