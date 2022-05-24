using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

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
            // выделить память для параметров отображения 
            NativeMethods.CRYPTUI_VIEWCERTIFICATE_STRUCT parameters = 
                new NativeMethods.CRYPTUI_VIEWCERTIFICATE_STRUCT(); 

            // указать размер структуры
            parameters.dwSize = Marshal.SizeOf(parameters); parameters.dwFlags = 0;

            // указать параметры диалога 
            parameters.hwndParent                       = hwnd;         // описатель родительского окна 
            parameters.szTitle                          = null;         // имя диалога

            // указать параметры назначения сертификата
            parameters.rgszPurposes                     = IntPtr.Zero;  // массив проверяемых назначений сертификата
            parameters.cPurposes                        = 0;            // число проверяемых назначений сертификата

            // указать параметры закладок
            parameters.rgPropSheetPages                 = IntPtr.Zero;  // массив описаний дополнительных закладок
            parameters.cPropSheetPages                  = 0;            // число дополнительных закладок
            parameters.nStartPage                       = 0;            // номер активной закладки
            
            // указать параметры по умолчанию
            parameters.pCryptProviderData               = IntPtr.Zero;  // только для WinVerifyTrust
            parameters.fpCryptProviderDataTrustedUsage  = false;        // только для WinVerifyTrust
            parameters.fCounterSigner                   = false;        // только для WinVerifyTrust
            parameters.idxSigner                        = 0;            // только для WinVerifyTrust
            parameters.idxCert                          = 0;            // только для WinVerifyTrust
            parameters.idxCounterSigner                 = 0;            // только для WinVerifyTrust

            // указать тип нового хранилища 
            IntPtr CERT_STORE_PROV_MEMORY = new IntPtr(2); uint CERT_STORE_CREATE_NEW_FLAG = 0x2000;

            // создать хранилище сертификатов
            using (CertificateStore certStore = new CertificateStore(
                CERT_STORE_PROV_MEMORY, CERT_STORE_CREATE_NEW_FLAG, IntPtr.Zero))
            {
                // для всех сертификатов
                for (int i = 1; i < certificateChain.Length; i++)
                {
                    // получить закодированное представление сертификата
                    byte[] encoded = certificateChain[i].Encoded; 

                    // добавить сертификат в хранилище
                    using (CertificateContext certContext = 
                        certStore.AddCertificate(encoded, CertificateStore.ADD_ALWAYS)) {} 
                }
                // выделить память для описателя
                parameters.rghStores = Marshal.AllocHGlobal(IntPtr.Size); 
                try { 
                    // указать число хранилищ
                    parameters.cStores = 1; bool fPropertiesChanged; 

                    // скопировать описатель
                    Marshal.WriteIntPtr(parameters.rghStores, 0, certStore.Handle); 

                    // создать контекст сертификата
                    using (CertificateContext certContext = 
                        new CertificateContext(certificateChain[0].Encoded))
                    {
                        // создать контекст сертификата
                        parameters.pCertContext = certContext.Handle; 

                        // отобразить сертификат
                        NativeMethods.CryptUIDlgViewCertificate(parameters, out fPropertiesChanged); 
                    }
                }
                // освободить выделенную память 
                finally { Marshal.FreeHGlobal(parameters.rghStores);  }
            }
        }
    }
}
