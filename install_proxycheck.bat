@echo off
setlocal

set "ARCH=x64"
set "URL=https://github.com/asroxy/proxycheck-cli/releases/download/v1.01/proxycheck_windows.zip"
set "TEMP_DIR=%TEMP%\proxycheck"

echo Downloading Proxycheck for Windows...
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('%URL%', '%TEMP_DIR%.zip')"

echo Extracting...
powershell -Command "Expand-Archive -Path '%TEMP_DIR%.zip' -DestinationPath '%TEMP_DIR%'"

echo Installing to C:\Windows...
move /Y "%TEMP_DIR%\proxycheck.exe" "C:\Windows\"

echo Cleaning up...
rd /s /q "%TEMP_DIR%"
del "%TEMP_DIR%.zip"

echo Installation complete.
endlocal
