@echo off
set TOOL=Aladdin.CRC.exe
set TOKEN=c7c86292dd1a865e
set DIRECTORY=%cd%
set FRAMEWORK=%DIRECTORY:~-4,4%
set VERSION=%DIRECTORY:~-14,9%

set V2_PATH=%SystemRoot%\assembly
set V2=%VERSION%20__%TOKEN%
set V2_RU=%VERSION%20_ru_%TOKEN%

set V4_PATH=%SystemRoot%\Microsoft.NET\assembly
set V4=v4.0_%VERSION%40__%TOKEN%
set V4_RU=v4.0_%VERSION%40_ru_%TOKEN%

if %FRAMEWORK%==v2.0 (
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin\%V2%\Aladdin.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.IO\%V2%\Aladdin.IO.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.Net\%V2%\Aladdin.Net.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.Net.TCP\%V2%\Aladdin.Net.TCP.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.Math\%V2%\Aladdin.Math.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.GUI\%V2%\Aladdin.GUI.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.GUI.resources\%V2_RU%\Aladdin.GUI.resources.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.ASN1\%V2%\Aladdin.ASN1.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.ASN1.ISO\%V2%\Aladdin.ASN1.ISO.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.ISO7816\%V2%\Aladdin.ISO7816.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.PCSC\%V2%\Aladdin.PCSC.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.PKCS11\%V2%\Aladdin.PKCS11.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI\%V2%\Aladdin.CAPI.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.resources\%V2_RU%\Aladdin.CAPI.resources.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.Proxy\%V2%\Aladdin.CAPI.Proxy.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.Bio.BSAPI\%V2%\Aladdin.CAPI.Bio.BSAPI.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.Bio.Athena\%V2%\Aladdin.CAPI.Bio.Athena.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.SCard\%V2%\Aladdin.CAPI.SCard.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.ANSI\%V2%\Aladdin.CAPI.ANSI.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.ANSI.GUI\%V2%\Aladdin.CAPI.ANSI.GUI.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.ANSI.GUI.resources\%V2_RU%\Aladdin.CAPI.ANSI.GUI.resources.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.ANSI.PKCS11\%V2%\Aladdin.CAPI.ANSI.PKCS11.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.GOST\%V2%\Aladdin.CAPI.GOST.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.GOST.GUI\%V2%\Aladdin.CAPI.GOST.GUI.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.GOST.GUI.resources\%V2_RU%\Aladdin.CAPI.GOST.GUI.resources.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.GOST.PKCS11\%V2%\Aladdin.CAPI.GOST.PKCS11.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.STB\%V2%\Aladdin.CAPI.STB.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.STB.GUI\%V2%\Aladdin.CAPI.STB.GUI.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.STB.GUI.resources\%V2_RU%\Aladdin.CAPI.STB.GUI.resources.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.KZ\%V2%\Aladdin.CAPI.KZ.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.KZ.GUI\%V2%\Aladdin.CAPI.KZ.GUI.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.KZ.GUI.resources\%V2_RU%\Aladdin.CAPI.KZ.GUI.resources.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.PKCS12\%V2%\Aladdin.CAPI.PKCS12.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.PKCS11\%V2%\Aladdin.CAPI.PKCS11.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.PKCS11.AKS\%V2%\Aladdin.CAPI.PKCS11.AKS.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.PKCS11.Athena\%V2%\Aladdin.CAPI.PKCS11.Athena.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.PKCS11.JaCarta\%V2%\Aladdin.CAPI.PKCS11.JaCarta.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.Environment\%V2%\Aladdin.CAPI.Environment.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.COM.NET\%V2%\Aladdin.CAPI.COM.NET.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_MSIL\Aladdin.CAPI.COM.Interop\%V2%\Aladdin.CAPI.COM.Interop.dll"

"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.SCard.APDU\%V2%\Aladdin.CAPI.SCard.APDU.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.Rnd\%V2%\Aladdin.CAPI.Rnd.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.Rnd.Bio\%V2%\Aladdin.CAPI.Rnd.Bio.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.Rnd.Accord\%V2%\Aladdin.CAPI.Rnd.Accord.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.Rnd.Sobol\%V2%\Aladdin.CAPI.Rnd.Sobol.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.CSP\%V2%\Aladdin.CAPI.CSP.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.CNG\%V2%\Aladdin.CAPI.CNG.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.ANSI.CSP.Microsoft\%V2%\Aladdin.CAPI.ANSI.CSP.Microsoft.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.ANSI.CSP.AKS\%V2%\Aladdin.CAPI.ANSI.CSP.AKS.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.ANSI.CSP.Athena\%V2%\Aladdin.CAPI.ANSI.CSP.Athena.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.ANSI.CNG.Microsoft\%V2%\Aladdin.CAPI.ANSI.CNG.Microsoft.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.GOST.CSP.CryptoPro\%V2%\Aladdin.CAPI.GOST.CSP.CryptoPro.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_32\Aladdin.CAPI.KZ.CSP.Tumar\%V2%\Aladdin.CAPI.KZ.CSP.Tumar.dll"

"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.SCard.APDU\%V2%\Aladdin.CAPI.SCard.APDU.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.Rnd\%V2%\Aladdin.CAPI.Rnd.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.Rnd.Bio\%V2%\Aladdin.CAPI.Rnd.Bio.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.Rnd.Accord\%V2%\Aladdin.CAPI.Rnd.Accord.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.Rnd.Sobol\%V2%\Aladdin.CAPI.Rnd.Sobol.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.CSP\%V2%\Aladdin.CAPI.CSP.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.CNG\%V2%\Aladdin.CAPI.CNG.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.ANSI.CSP.Microsoft\%V2%\Aladdin.CAPI.ANSI.CSP.Microsoft.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.ANSI.CSP.AKS\%V2%\Aladdin.CAPI.ANSI.CSP.AKS.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.ANSI.CSP.Athena\%V2%\Aladdin.CAPI.ANSI.CSP.Athena.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.ANSI.CNG.Microsoft\%V2%\Aladdin.CAPI.ANSI.CNG.Microsoft.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.GOST.CSP.CryptoPro\%V2%\Aladdin.CAPI.GOST.CSP.CryptoPro.dll"
"%TOOL%" -256 "%V2_PATH%\GAC_64\Aladdin.CAPI.KZ.CSP.Tumar\%V2%\Aladdin.CAPI.KZ.CSP.Tumar.dll"
)

if %FRAMEWORK%==v4.0 (
set TOOL=..\v2.0\Aladdin.CRC.exe
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin\%V4%\Aladdin.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.IO\%V4%\Aladdin.IO.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.Net\%V4%\Aladdin.Net.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.Net.TCP\%V4%\Aladdin.Net.TCP.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.Math\%V4%\Aladdin.Math.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.GUI\%V4%\Aladdin.GUI.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.GUI.resources\%V4_RU%\Aladdin.GUI.resources.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.ASN1\%V4%\Aladdin.ASN1.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.ASN1.ISO\%V4%\Aladdin.ASN1.ISO.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.ISO7816\%V4%\Aladdin.ISO7816.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.PCSC\%V4%\Aladdin.PCSC.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.PKCS11\%V4%\Aladdin.PKCS11.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI\%V4%\Aladdin.CAPI.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.resources\%V4_RU%\Aladdin.CAPI.resources.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.Proxy\%V4%\Aladdin.CAPI.Proxy.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.Bio.BSAPI\%V4%\Aladdin.CAPI.Bio.BSAPI.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.Bio.Athena\%V4%\Aladdin.CAPI.Bio.Athena.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.SCard\%V4%\Aladdin.CAPI.SCard.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.ANSI\%V4%\Aladdin.CAPI.ANSI.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.ANSI.GUI\%V4%\Aladdin.CAPI.ANSI.GUI.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.ANSI.GUI.resources\%V4_RU%\Aladdin.CAPI.ANSI.GUI.resources.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.ANSI.PKCS11\%V4%\Aladdin.CAPI.ANSI.PKCS11.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.GOST\%V4%\Aladdin.CAPI.GOST.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.GOST.GUI\%V4%\Aladdin.CAPI.GOST.GUI.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.GOST.GUI.resources\%V4_RU%\Aladdin.CAPI.GOST.GUI.resources.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.GOST.PKCS11\%V4%\Aladdin.CAPI.GOST.PKCS11.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.STB\%V4%\Aladdin.CAPI.STB.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.STB.GUI\%V4%\Aladdin.CAPI.STB.GUI.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.STB.GUI.resources\%V4_RU%\Aladdin.CAPI.STB.GUI.resources.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.KZ\%V4%\Aladdin.CAPI.KZ.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.KZ.GUI\%V4%\Aladdin.CAPI.KZ.GUI.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.KZ.GUI.resources\%V4_RU%\Aladdin.CAPI.KZ.GUI.resources.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.PKCS12\%V4%\Aladdin.CAPI.PKCS12.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.PKCS11\%V4%\Aladdin.CAPI.PKCS11.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.PKCS11.AKS\%V4%\Aladdin.CAPI.PKCS11.AKS.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.PKCS11.Athena\%V4%\Aladdin.CAPI.PKCS11.Athena.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.PKCS11.JaCarta\%V4%\Aladdin.CAPI.PKCS11.JaCarta.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.Environment\%V4%\Aladdin.CAPI.Environment.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.COM.NET\%V4%\Aladdin.CAPI.COM.NET.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_MSIL\Aladdin.CAPI.COM.Interop\%V4%\Aladdin.CAPI.COM.Interop.dll"

"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.SCard.APDU\%V4%\Aladdin.CAPI.SCard.APDU.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.Rnd\%V4%\Aladdin.CAPI.Rnd.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.Rnd.Bio\%V4%\Aladdin.CAPI.Rnd.Bio.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.Rnd.Accord\%V4%\Aladdin.CAPI.Rnd.Accord.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.Rnd.Sobol\%V4%\Aladdin.CAPI.Rnd.Sobol.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.CSP\%V4%\Aladdin.CAPI.CSP.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.CNG\%V4%\Aladdin.CAPI.CNG.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.ANSI.CSP.Microsoft\%V4%\Aladdin.CAPI.ANSI.CSP.Microsoft.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.ANSI.CSP.AKS\%V4%\Aladdin.CAPI.ANSI.CSP.AKS.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.ANSI.CSP.Athena\%V4%\Aladdin.CAPI.ANSI.CSP.Athena.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.ANSI.CNG.Microsoft\%V4%\Aladdin.CAPI.ANSI.CNG.Microsoft.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.GOST.CSP.CryptoPro\%V4%\Aladdin.CAPI.GOST.CSP.CryptoPro.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_32\Aladdin.CAPI.KZ.CSP.Tumar\%V4%\Aladdin.CAPI.KZ.CSP.Tumar.dll"

"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.SCard.APDU\%V4%\Aladdin.CAPI.SCard.APDU.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.Rnd\%V4%\Aladdin.CAPI.Rnd.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.Rnd.Bio\%V4%\Aladdin.CAPI.Rnd.Bio.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.Rnd.Accord\%V4%\Aladdin.CAPI.Rnd.Accord.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.Rnd.Sobol\%V4%\Aladdin.CAPI.Rnd.Sobol.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.CSP\%V4%\Aladdin.CAPI.CSP.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.CNG\%V4%\Aladdin.CAPI.CNG.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.ANSI.CSP.Microsoft\%V4%\Aladdin.CAPI.ANSI.CSP.Microsoft.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.ANSI.CSP.AKS\%V4%\Aladdin.CAPI.ANSI.CSP.AKS.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.ANSI.CSP.Athena\%V4%\Aladdin.CAPI.ANSI.CSP.Athena.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.ANSI.CNG.Microsoft\%V4%\Aladdin.CAPI.ANSI.CNG.Microsoft.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.GOST.CSP.CryptoPro\%V4%\Aladdin.CAPI.GOST.CSP.CryptoPro.dll"
"%TOOL%" -256 "%V4_PATH%\GAC_64\Aladdin.CAPI.KZ.CSP.Tumar\%V4%\Aladdin.CAPI.KZ.CSP.Tumar.dll"
)
if exist "%cd%\..\Aladdin.CAPI.COM.dll" (
"%TOOL%" -256 "%cd%\..\Aladdin.CAPI.COM.dll"
)
if exist "%cd%\..\Aladdin.CAPI.SO.dll" (
"%TOOL%" -256 "%cd%\..\Aladdin.CAPI.SO.dll"
)
"%TOOL%" -256 "%cd%\Aladdin.CAPI.Store.exe"
"%TOOL%" -256 "%cd%\%TOOL%"
