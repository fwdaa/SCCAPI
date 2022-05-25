using System;
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // CryptoAPI-контекст сертификата
    ///////////////////////////////////////////////////////////////////////////
    public class CertificateContext : RefObject
    {
        // конструктор
        public CertificateContext(IntPtr handle) { this.handle = handle; }

        // конструктор
        public CertificateContext(byte[] encoded)
        {
            // создать контекст сертификата
            handle = NativeMethods.CertCreateCertificateContext(
                1, encoded, encoded.Length
            ); 
            // при возникновении ошибки 
            if (handle == IntPtr.Zero) Marshal.ThrowExceptionForHR( 
                Marshal.GetHRForLastWin32Error()
            ); 
        }
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            NativeMethods.CertFreeCertificateContext(handle); base.OnDispose();
        }
        // описатель контекста сертификата
        public IntPtr Handle { get { return handle; }} private IntPtr handle; 

        // удалить сертификат из хранилища
        public void DeleteFromStore()
        {
            // удалить сертификат из хранилища
            if (!NativeMethods.CertDeleteCertificateFromStore(handle))
            {
                // при возникновении ошибки выбросить исключение
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error()); 
            }
        }
    }
}
