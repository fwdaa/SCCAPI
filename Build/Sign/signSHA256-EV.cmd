@echo off
if '%2'=='' goto :usage
goto :start

:usage

echo.
echo Usage:
echo   signSHA256-EV.cmd $(Configuration) $(TargetPath) [$(Options)]
exit /b 1

:start

set PFX_PATH="%~dp0Aladdin-RD-ZAO-SHA256-EV.pfx"
set THUMBPRINT=0e5c2168c2476e3bc39035edf098c89d383918b7
set CROSS_PATH="%~dp0GlobalSignRootCA-MS-SHA256.cer"

call "%~dp0sign.cmd" %1 %2 SHA256 %PFX_PATH% 1234567890 %THUMBPRINT% %CROSS_PATH% %3

