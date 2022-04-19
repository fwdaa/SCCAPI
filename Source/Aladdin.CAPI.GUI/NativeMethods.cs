using System; 
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Вызов методов из внешних модулей
    ///////////////////////////////////////////////////////////////////////////
    internal static class NativeMethods    
    {        
		// функция определения раскладки клавиатуры
		[DllImport("user32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet=CharSet.Auto, ExactSpelling = true)]
		internal static extern IntPtr GetKeyboardLayout(int dwLayout);

        // синхронная передача сообщений
 		[DllImport("user32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Auto)]
		internal static extern IntPtr SendMessage(
            IntPtr hwnd, Int32 msg, IntPtr wParam, IntPtr lParam
        );
        // ассинхронная передача сообщений
 		[DllImport("user32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Auto)]
		internal static extern bool PostMessage(
            IntPtr hwnd, Int32 msg, IntPtr wParam, IntPtr lParam
        );
        [DllImport("user32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Auto)]
        internal static extern IntPtr SetParent(IntPtr hwnd, IntPtr hParent);

        // структура параметров для функции CryptUIDlgViewCertificate
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRYPTUI_VIEWCERTIFICATE_STRUCT : IDisposable {
            [MarshalAs(UnmanagedType.U4)]
            internal int      dwSize;
            internal IntPtr   hwndParent;                           // OPTIONAL
            [MarshalAs(UnmanagedType.U4)]
            internal UInt32   dwFlags;                              // OPTIONAL
            [MarshalAs(UnmanagedType.LPWStr)]
            internal String   szTitle;                              // OPTIONAL
            internal IntPtr   pCertContext;                         // REQUIRED
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)]
            internal String[] rgszPurposes;                         // OPTIONAL
            [MarshalAs(UnmanagedType.U4)]
            internal UInt32   cPurposes;                            // OPTIONAL
            internal IntPtr   pCryptProviderData;                   // OPTIONAL
            [MarshalAs(UnmanagedType.Bool)]
            internal Boolean  fpCryptProviderDataTrustedUsage;      // OPTIONAL
            [MarshalAs(UnmanagedType.U4)]
            internal UInt32   idxSigner;                            // OPTIONAL
            [MarshalAs(UnmanagedType.U4)]
            internal UInt32   idxCert;                              // OPTIONAL
            [MarshalAs(UnmanagedType.Bool)]
            internal Boolean  fCounterSigner;                       // OPTIONAL
            [MarshalAs(UnmanagedType.U4)]
            internal UInt32   idxCounterSigner;                     // OPTIONAL
            [MarshalAs(UnmanagedType.U4)]
            internal UInt32   cStores;                              // OPTIONAL
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 13)]
            internal IntPtr[] rghStores;                            // OPTIONAL
            [MarshalAs(UnmanagedType.U4)]
            internal UInt32   cPropSheetPages;                      // OPTIONAL
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 15)]
            internal IntPtr[] rgPropSheetPages;                     // OPTIONAL
            [MarshalAs(UnmanagedType.U4)]
            internal UInt32   nStartPage;                           // OPTIONAL

            public void Dispose() {}
        }
        // отобразить сертификат
        [DllImport("cryptui.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CryptUIDlgViewCertificate(
            [In, MarshalAs(UnmanagedType.LPStruct)] CRYPTUI_VIEWCERTIFICATE_STRUCT ViewInfo,
            [In, Out] IntPtr pfPropertiesChanged
        );    
        // создать контекст сертификата
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CertCreateCertificateContext(
            [In] UInt32 dwCertEncodingType, 
            [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] pbCertEncoded, 
            [In] int cbCertEncoded
        ); 
        // закрыть контекст сертификата
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CertFreeCertificateContext([In] IntPtr hCertStore); 

        // создать хранилище
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CertOpenStore(
            [In] IntPtr lpszStoreProvider, [In] UInt32 dwEncodingType, 
            [In] IntPtr hCryptProv, [In] UInt32 dwFlags, [In] IntPtr pvPara
        ); 
        // добавить сертификат в хранилище
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CertAddCertificateContextToStore(
            [In] IntPtr hCertStore, [In] IntPtr pCertContext,
            [In] UInt32 dwAddDisposition, [In, Optional] IntPtr ppStoreContext
        );
        // закрыть хранилище
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CertCloseStore(
            [In] IntPtr hCertStore, [In] UInt32 dwFlags
        ); 
    }
}
