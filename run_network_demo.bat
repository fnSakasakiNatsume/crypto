@echo off
echo ========================================
echo TLS 网络通信演示
echo ========================================
echo.
echo 此演示需要两台电脑或两个终端窗口
echo.
echo 步骤：
echo 1. 在第一个终端运行: run_server.bat
echo 2. 在第二个终端运行: run_client.bat
echo.
echo 或者在同一台电脑上：
echo 1. 打开第一个命令提示符，运行: run_server.bat
echo 2. 打开第二个命令提示符，运行: run_client.bat
echo.
echo 按任意键继续查看说明...
pause >nul
echo.
echo 如需连接到其他电脑的服务器：
echo 1. 修改 TLSClient.java 中的 SERVER_HOST 为服务器IP
echo 2. 重新编译: compile.bat
echo 3. 运行客户端: run_client.bat
echo.
pause
