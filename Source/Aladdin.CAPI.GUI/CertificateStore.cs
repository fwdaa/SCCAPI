using System;
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // CryptoAPI-контекст хранилища сертификатов
    ///////////////////////////////////////////////////////////////////////////
    public class CertificateStore : RefObject
    {
        // способ добавления сертификата
        public const uint ADD_NEW                                  = 1;
        public const uint ADD_USE_EXISTING                         = 2;
        public const uint ADD_REPLACE_EXISTING                     = 3;
        public const uint ADD_ALWAYS                               = 4;
        public const uint ADD_REPLACE_EXISTING_INHERIT_PROPERTIES  = 5;
        public const uint ADD_NEWER                                = 6;
        public const uint ADD_NEWER_INHERIT_PROPERTIES             = 7;

        // конструктор
        public CertificateStore(string storeProvider, uint dwFlags, IntPtr pvPara)
        {
            // получить закодированное представление имени
            IntPtr ptr = Marshal.StringToHGlobalAnsi(storeProvider); 
            try {  
                // создать хранилище сертификатов
                handle = NativeMethods.CertOpenStore(ptr, 1, IntPtr.Zero, dwFlags, pvPara); 

                // при возникновении ошибки 
                if (handle == IntPtr.Zero) Marshal.ThrowExceptionForHR( 
                    Marshal.GetHRForLastWin32Error()
                ); 
            }
            // освободить выделенные ресурсы
            finally { Marshal.FreeHGlobal(ptr); }
        }
        // конструктор
        public CertificateStore(IntPtr storeProvider, uint dwFlags, IntPtr pvPara)
        {
            // создать хранилище сертификатов
            handle = NativeMethods.CertOpenStore(
                storeProvider, 1, IntPtr.Zero, dwFlags, pvPara
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
            NativeMethods.CertCloseStore(handle, 0); base.OnDispose();
        }
        // описатель контекста сертификата
        public IntPtr Handle { get { return handle; }} private IntPtr handle; 

        // добавить сертификат в хранилище
        public CertificateContext AddCertificate(byte[] encoded, uint addDisposition)
        {
            // выделить память для описателя
            IntPtr ptr = Marshal.AllocHGlobal(IntPtr.Size); 
            try {  
                // создать контекст сертификата
                using (CertificateContext certContext = new CertificateContext(encoded))
                { 
                    // добавить сертификат в хранилище
                    if (!NativeMethods.CertAddCertificateContextToStore(
                        handle, certContext.Handle, addDisposition, ptr))
                    {
                        // при возникновении ошибки выбросить исключение
                        Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error()); 
                    }
                    // вернуть контекст сертификата
                    return new CertificateContext(Marshal.ReadIntPtr(ptr)); 
                }
            }
            // освободить выделенные ресурсы
            finally { Marshal.FreeHGlobal(ptr); }
        }
    }
}
