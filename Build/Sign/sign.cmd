@echo off
if '%6'=='' goto :usage
goto :start

rem Используемый контейнер .pfx должен содержать все сертификаты цепочки доверия, поскольку при 
rem указании контейнера (/f) нельзя указать использование сертификатов системного хранилища (/sm). 
rem Кроме того, все сертификаты контейнера будут помещены в подписываемый файл только при 
rem указании кросс-сертификата (/ac). В противном случае, в подписываемый файл не попадет 
rem корневой сертификат цепочки доверия (при наличии в цепочке промежуточных сертификатов). 

:usage

echo.
echo Usage:
echo   sign.cmd $(Configuration) $(TargetPath) $(Hash) $(PfxPath) $(Password) $(Thumbprint) [$(CrossCertificatePath)] [$(Options)]
exit /b 1

:start

set CONFIGURATION=%1
set TARGET_PATH=%2
set HASH_TYPE=%3
set PFX_PATH=%4
set PASSWORD=%5
set THUMBPRINT=%6
set CROSS_PATH=%7
set OPTIONS=%8

:prepare1
if '%CONFIGURATION%'=='' goto :prepare2
if not '%CONFIGURATION:~0,1%%CONFIGURATION:~0,1%'=='""' goto :prepare2
set CONFIGURATION=%CONFIGURATION:~1,-1%

:prepare2
if '%TARGET_PATH%'=='' goto :prepare3
if not '%TARGET_PATH:~0,1%%TARGET_PATH:~0,1%'=='""' goto :prepare3
set TARGET_PATH=%TARGET_PATH:~1,-1%

:prepare3
if '%HASH_TYPE%'=='' goto :prepare4
if not '%HASH_TYPE:~0,1%%HASH_TYPE:~0,1%'=='""' goto :prepare4
set HASH_TYPE=%HASH_TYPE:~1,-1%

:prepare4
if '%PFX_PATH%'=='' goto :prepare5
if not '%PFX_PATH:~0,1%%PFX_PATH:~0,1%'=='""' goto :prepare5
set PFX_PATH=%PFX_PATH:~1,-1%

:prepare5
if '%PASSWORD%'=='' goto :prepare6
if not '%PASSWORD:~0,1%%PASSWORD:~0,1%'=='""' goto :prepare6
set PASSWORD=%PASSWORD:~1,-1%

:prepare6
if '%THUMBPRINT%'=='' goto :prepare7
if not '%THUMBPRINT:~0,1%%THUMBPRINT:~0,1%'=='""' goto :prepare7
set THUMBPRINT=%THUMBPRINT:~1,-1%

:prepare7
if '%CROSS_PATH%'=='' goto :prepare8
if not '%CROSS_PATH:~0,1%%CROSS_PATH:~0,1%'=='""' goto :prepare8
set CROSS_PATH=%CROSS_PATH:~1,-1%

:prepare8
if '%OPTIONS%'=='' goto :debugcheck
if not '%OPTIONS:~0,1%%OPTIONS:~0,1%'=='""' goto :debugcheck
set OPTIONS=%OPTIONS:~1,-1%

:debugcheck
if '%CONFIGURATION%'=='Debug' goto :exit

:timecheck
set TIMESTAMP=/t http://timestamp.verisign.com/scripts/timstamp.dll
if '%HASH_TYPE%'=='SHA1' goto :optioncheck
if '%HASH_TYPE%'=='sha1' goto :optioncheck
set TIMESTAMP=/tr http://timestamp.globalsign.com/?signature=sha2 /td %HASH_TYPE%
rem set TIMESTAMP=

:optioncheck
if '%CROSS_PATH%'      ==''  goto :sign
if '%CROSS_PATH:~0,1%' =='/' goto :optionshift

set SIGN_OPTIONS=/ac "%CROSS_PATH%" %OPTIONS%
set VERIFY_OPTIONS=/kp 
goto :sign

:optionshift
set SIGN_OPTIONS=%CROSS_PATH% 
set VERIFY_OPTIONS=/all

:sign
set SOURCE=/f "%PFX_PATH%" /p %PASSWORD% 
rem set SOURCE=/sm /sha1 %THUMBPRINT%

cmd /c signtool.exe sign %SOURCE% /fd %HASH_TYPE% /ph %SIGN_OPTIONS% %TIMESTAMP% /v "%TARGET_PATH%"
cmd /c signtool.exe verify /tw %VERIFY_OPTIONS% /v "%TARGET_PATH%"

:exit
cmd /c exit 0
