using System;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.GUI
{
    public static class CertificateDialog
    {
        ///////////////////////////////////////////////////////////////////////
	    // Отобразить цепочку сертификатов
        ///////////////////////////////////////////////////////////////////////
	    public static void Show(IntPtr hwnd, Certificate[] certificateChain)
        {
            // для частного случая
            if (certificateChain.Length == 1)
            {
		        // создать объект сертификата
		        X509Certificate2 cert = new X509Certificate2(certificateChain[0].Encoded); 

		        // отобразить сертификат
		        X509Certificate2UI.DisplayCertificate(cert, hwnd); return; 
            }
            // создать список хранилищ
            IntPtr[] hCertStores = new IntPtr[] { CreateCertChainStore(certificateChain) };  
            
            // выделить память для параметров отображения 
            NativeMethods.CRYPTUI_VIEWCERTIFICATE_STRUCT parameters = 
                new NativeMethods.CRYPTUI_VIEWCERTIFICATE_STRUCT(); 

            // указать размер структуры
            parameters.dwSize = Marshal.SizeOf(parameters); 

            // указать опции функции 
            parameters.dwFlags = NativeMethods.CRYPTUI_DONT_OPEN_STORES; 

            // указать параметры диалога 
            parameters.hwndParent       = hwnd;         // описатель родительского окна 
            parameters.szTitle          = null;         // имя диалога

            // указать параметры назначения сертификата
            parameters.rgszPurposes     = null;         // массив проверяемых назначений сертификата
            parameters.cPurposes        = 0;            // число проверяемых назначений сертификата

            // указать используемые хранилища
            parameters.rghStores        = hCertStores;  // массив дополнительных хранилищ сертификатов
            parameters.cStores          = 1;            // число дополнительных хранилищ сертификатов

            // указать параметры закладок
            parameters.rgPropSheetPages = IntPtr.Zero;  // массив описаний дополнительных закладок
            parameters.cPropSheetPages  = 0;            // число дополнительных закладок
            parameters.nStartPage       = 0;            // номер активной закладки
            
            // указать параметры по умолчанию
            parameters.pCryptProviderData               = IntPtr.Zero;  // только для WinVerifyTrust
            parameters.fpCryptProviderDataTrustedUsage  = false;        // только для WinVerifyTrust
            parameters.fCounterSigner                   = false;        // только для WinVerifyTrust
            parameters.idxSigner                        = 0;            // только для WinVerifyTrust
            parameters.idxCert                          = 0;            // только для WinVerifyTrust
            parameters.idxCounterSigner                 = 0;            // только для WinVerifyTrust
            try { 
                // получить закодированное представление
                byte[] encoded = certificateChain[0].Encoded; UInt32 X509_ASN_ENCODING = 1; 

                // создать контекст сертификата
                parameters.pCertContext = NativeMethods.CertCreateCertificateContext(
                    X509_ASN_ENCODING, encoded, encoded.Length
                ); 
                // при возникновении ошибки 
                if (parameters.pCertContext == IntPtr.Zero) 
                {
                    // выбросить исключение
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error()); 
                }
                // отобразить сертификат
                bool fPropertiesChanged; 
                if (!NativeMethods.CryptUIDlgViewCertificate(parameters, out fPropertiesChanged))
                {
                    // при ошибке выбросить исключение
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error()); 
                }
            }
            // закрыть хранилище сертификатов
            finally { NativeMethods.CertCloseStore(hCertStores[0], 0);  }
        }
        ///////////////////////////////////////////////////////////////////////
        // Создать хранилище для цепочки сертификатов
        ///////////////////////////////////////////////////////////////////////
        private static IntPtr CreateCertChainStore(Certificate[] certificateChain)
        {
            // указать тип хранилища и сертификатов
            IntPtr CERT_STORE_PROV_MEMORY = new IntPtr(2); UInt32 X509_ASN_ENCODING = 1; 

            // указать создание нового хранилища
            UInt32 CERT_STORE_CREATE_NEW_FLAG = 0x2000; UInt32 CERT_STORE_ADD_ALWAYS = 4;

            // создать хранилище сертификатов
            IntPtr hCertStore = NativeMethods.CertOpenStore(CERT_STORE_PROV_MEMORY, 
                X509_ASN_ENCODING, IntPtr.Zero, CERT_STORE_CREATE_NEW_FLAG, IntPtr.Zero
            ); 
            // при возникновении ошибки выбросить исключение
            if (hCertStore == IntPtr.Zero) Marshal.ThrowExceptionForHR(
                Marshal.GetHRForLastWin32Error()
            ); 
            // для всех сертификатов
            for (int i = 1; i < certificateChain.Length; i++)
            {
                // получить закодированное представление
                byte[] encoded = certificateChain[i].Encoded; 

                // создать контекст сертификата
                IntPtr hCertContext = NativeMethods.CertCreateCertificateContext(
                    X509_ASN_ENCODING, encoded, encoded.Length
                ); 
                // при возникновении ошибки 
                if (hCertContext == IntPtr.Zero) Marshal.ThrowExceptionForHR( 
                    Marshal.GetHRForLastWin32Error()
                ); 
                try { 
                    // добавить сертификат в хранилище
                    if (!NativeMethods.CertAddCertificateContextToStore(
                        hCertStore, hCertContext, CERT_STORE_ADD_ALWAYS, IntPtr.Zero))
                    {
                        // при возникновении ошибки выбросить исключение
                        Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error()); 
                    }
                }
                // закрыть контекст сертификата
                finally { NativeMethods.CertFreeCertificateContext(hCertContext); }
            }
            return hCertStore; 
        }
    }
}
