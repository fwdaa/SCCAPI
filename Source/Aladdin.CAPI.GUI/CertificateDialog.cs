using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.GUI
{
    public static class CertificateDialog
    {
        ///////////////////////////////////////////////////////////////////////
	    // Отобразить цепочку сертификатов
        ///////////////////////////////////////////////////////////////////////
        [SecurityCritical]
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

            // указать родительское окно 
            parameters.hwndParent = hwnd; parameters.dwFlags = 0; parameters.szTitle = null;

            // указать параметры назначения сертификата
            parameters.rgszPurposes = null; parameters.cPurposes = 0;

            // указать параметры по умолчанию
            parameters.idxSigner = 0; parameters.idxCert = 0;

            // указать параметры по умолчанию
            parameters.fCounterSigner = false; parameters.idxCounterSigner = 0;

            // указать используемые хранилища
            parameters.cStores = 1; parameters.rghStores = hCertStores;

            // указать параметры закладок
            parameters.cPropSheetPages = 0; parameters.rgPropSheetPages = null; 
            
            // указать параметры по умолчанию
            parameters.pCryptProviderData = IntPtr.Zero; parameters.nStartPage = 0;

            // указать параметры по умолчанию
            parameters.fpCryptProviderDataTrustedUsage = false;
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
                if (!NativeMethods.CryptUIDlgViewCertificate(parameters, IntPtr.Zero))
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
        [SecurityCritical]
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
            if (hCertStore == IntPtr.Zero) Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error()); 

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
                if (hCertContext == IntPtr.Zero) 
                {
                    // выбросить исключение
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error()); 
                }
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
