@echo off
if '%2'=='' goto :usage
goto :start

:usage

echo.
echo Usage:
echo   signSHA256.cmd $(Configuration) $(TargetPath) [$(Options)]
exit /b 1

:start

set PFX_PATH="%~dp0Aladdin-RD-ZAO-SHA256.pfx"
set THUMBPRINT=6ac12312167ac8a982c499f1d16ce26d9e5be264
set CROSS_PATH="%~dp0GlobalSignRootCA-MS-SHA256.cer"

call "%~dp0sign.cmd" %1 %2 SHA256 %PFX_PATH% 1234567890 %THUMBPRINT% %CROSS_PATH% %3

