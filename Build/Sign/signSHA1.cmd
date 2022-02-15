@echo off
if '%2'=='' goto :usage
goto :start

:usage

echo.
echo Usage:
echo   signSHA1.cmd $(Configuration) $(TargetPath) [$(Options)]
exit /b 1

:start

set PFX_PATH="%~dp0Aladdin-RD-ZAO-SHA1.pfx"
set THUMBPRINT=422F89951CD892AA2F1AE6DE492637E2D7F88859
set CROSS_PATH="%~dp0GlobalSignRootCA-MS-SHA1.cer"

call "%~dp0sign.cmd" %1 %2 SHA1 %PFX_PATH% 1234567890 %THUMBPRINT% %CROSS_PATH% %3

