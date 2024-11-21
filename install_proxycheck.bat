@echo off
setlocal

REM Determine the OS type
set "ARCH=x64"
set "URL=https://github.com/asroxy/proxycheck-cli/releases/download/v1.01/proxycheck_windows.zip"
set "TEMP_DIR=%TEMP%\proxycheck"

REM Download the file
echo Downloading Proxycheck for Windows...
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('%URL%', '%TEMP_DIR%.zip')"

REM Extract the ZIP file
echo Extracting...
powershell -Command "Expand-Archive -Path '%TEMP_DIR%.zip' -DestinationPath '%TEMP_DIR%'"

REM Move to C:\Windows
echo Installing to C:\Windows...
move /Y "%TEMP_DIR%\proxycheck.exe" "C:\Windows\"

REM Clean up
echo Cleaning up...
rd /s /q "%TEMP_DIR%"
del "%TEMP_DIR%.zip"

echo Installation complete.
endlocal
