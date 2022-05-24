using System; 
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis; 

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

        ///////////////////////////////////////////////////////////////////////
        // Опции для CryptUIDlgViewCertificate
        ///////////////////////////////////////////////////////////////////////
        
        internal const uint CRYPTUI_DISABLE_HTMLLINK                            = 0x00010000;   // недоступность справочных ссылок на вкладках
        internal const uint CRYPTUI_ACCEPT_DECLINE_STYLE                        = 0x00000040;   // отсутствие запроса подтверждения выбранного действия 

        // Вкладка General
        internal const uint CRYPTUI_DISABLE_ADDTOSTORE                          = 0x00000010;   // недоступность кнопки Install Certificate
        internal const uint CRYPTUI_ENABLE_ADDTOSTORE                           = 0x00000020;   // доступность кнопки Install Certificate
        internal const uint CRYPTUI_DISABLE_ISSUERSTATEMENT                     = 0x00020000;   // недоступность кнопки Issuer Statement

        // Вкладка Details
        internal const uint CRYPTUI_HIDE_DETAILPAGE                             = 0x00000002;   // отсутствие вкладки Details
        internal const uint CRYPTUI_DISABLE_EDITPROPERTIES                      = 0x00000004;   // недоступность кнопки Edit Properties
        internal const uint CRYPTUI_ENABLE_EDITPROPERTIES                       = 0x00000008;   // доступность кнопки Edit Properties
        internal const uint CRYPTUI_DISABLE_EXPORT                              = 0x00002000;   // недоступность кнопки Copy To File

        // Вкладка CertificationPath
        internal const uint CRYPTUI_HIDE_HIERARCHYPAGE                          = 0x00000001;   // отсутствие вкладки CertificationPath
        internal const uint CRYPTUI_IGNORE_UNTRUSTED_ROOT                       = 0x00000080;   // игнорирование незавершения цепочки доверенным сертификатом 

        // Сертификаты для удаленной машины
        internal const uint CRYPTUI_WARN_UNTRUSTED_ROOT                         = 0x00000400;   // цепочка сертификатов предназначена для удаленной машины
        internal const uint CRYPTUI_WARN_REMOTE_TRUST                           = 0x00001000;   // предупреждение о возможной недостоверности цепочки для удаленной машины

        // Использование стандартных хранилищ сертификатов 
        internal const uint CRYPTUI_DONT_OPEN_STORES                            = 0x00000100;   // отсутствие использования стандартных хранилищ сертификатов 
        internal const uint CRYPTUI_ONLY_OPEN_ROOT_STORE                        = 0x00000200;   // использование только Root из стандартных хранилищ сертификатов

        // Проверка отозванности сертификатов
        internal const uint CRYPTUI_ENABLE_REVOCATION_CHECK_END_CERT            = 0x00004000;   // проверка отозванности для сертификата пользователя 
        internal const uint CRYPTUI_ENABLE_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT  = 0x00000800;   // проверка отозванности для всех сертификатов цепочки, кроме корневого
        internal const uint CRYPTUI_ENABLE_REVOCATION_CHECK_CHAIN               = 0x00008000;   // проверка отозванности для всех сертификатов цепочки 
        internal const uint CRYPTUI_CACHE_ONLY_URL_RETRIEVAL                    = 0x00040000;   // использование только offline-проверки отозванных сертификатов

        ///////////////////////////////////////////////////////////////////////
        // Диалог отображения сертификата
        ///////////////////////////////////////////////////////////////////////
        [SuppressMessage("Microsoft.Design", "CA1049: Types that own native resources should be disposable")]
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal class CRYPTUI_VIEWCERTIFICATE_STRUCT {
            [MarshalAs(UnmanagedType.I4)]
            internal Int32      dwSize;                             // размер структуры в байтах
            [MarshalAs(UnmanagedType.SysUInt)]
            internal IntPtr   hwndParent;                           // родительское окно
            [MarshalAs(UnmanagedType.U4)]
            internal UInt32   dwFlags;                              // опции для CryptUIDlgViewCertificate
            [MarshalAs(UnmanagedType.LPWStr)]
            internal String   szTitle;                              // имя диалога
            [MarshalAs(UnmanagedType.SysUInt)]
            internal IntPtr   pCertContext;                         // контекст сертификата
            [MarshalAs(UnmanagedType.SysUInt)] 
            internal IntPtr rgszPurposes;                           // массив проверяемых назначений сертификата
            [MarshalAs(UnmanagedType.I4)]
            internal Int32   cPurposes;                             // число проверяемых назначений сертификата
            [MarshalAs(UnmanagedType.SysUInt)]
            internal IntPtr   pCryptProviderData;                   // используется только с WinVerifyTrust
            [MarshalAs(UnmanagedType.Bool)]
            internal Boolean  fpCryptProviderDataTrustedUsage;      // используется только с WinVerifyTrust
            [MarshalAs(UnmanagedType.I4)]
            internal Int32   idxSigner;                             // используется только с WinVerifyTrust
            [MarshalAs(UnmanagedType.I4)]
            internal Int32   idxCert;                               // используется только с WinVerifyTrust
            [MarshalAs(UnmanagedType.Bool)]
            internal Boolean  fCounterSigner;                       // используется только с WinVerifyTrust
            [MarshalAs(UnmanagedType.I4)]
            internal Int32   idxCounterSigner;                      // используется только с WinVerifyTrust
            [MarshalAs(UnmanagedType.I4)]
            internal Int32   cStores;                               // число дополнительных хранилищ сертификатов
            [MarshalAs(UnmanagedType.SysUInt)]
            internal IntPtr rghStores;                              // массив дополнительных хранилищ сертификатов
            [MarshalAs(UnmanagedType.I4)]
            internal Int32   cPropSheetPages;                       // число дополнительных закладок
            [MarshalAs(UnmanagedType.SysUInt)]
            internal IntPtr   rgPropSheetPages;                     // массив описаний дополнительных закладок
            [MarshalAs(UnmanagedType.I4)]
            internal Int32   nStartPage;                            // номер активной закладки
        }
        // отобразить сертификат
        [DllImport("cryptui.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CryptUIDlgViewCertificate(
            [In,  MarshalAs(UnmanagedType.LPStruct)] CRYPTUI_VIEWCERTIFICATE_STRUCT ViewInfo,
            [Out, MarshalAs(UnmanagedType.Bool)] out bool fPropertiesChanged
        );    
        ///////////////////////////////////////////////////////////////////////
        // Контекст сертификата
        ///////////////////////////////////////////////////////////////////////

        // создать контекст сертификата
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CertCreateCertificateContext(
            [In, MarshalAs(UnmanagedType.U4)] UInt32 dwCertEncodingType, 
            [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] byte[] pbCertEncoded, 
            [In, MarshalAs(UnmanagedType.U4)] int cbCertEncoded
        ); 
        // закрыть контекст сертификата
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CertFreeCertificateContext(
            [In, MarshalAs(UnmanagedType.SysUInt)] IntPtr hCertStore
        ); 
        ///////////////////////////////////////////////////////////////////////
        // Хранилища сертификатов
        ///////////////////////////////////////////////////////////////////////
        
        // создать или открыть хранилище
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CertOpenStore(
            [In, MarshalAs(UnmanagedType.SysUInt)] IntPtr lpszStoreProvider, 
            [In, MarshalAs(UnmanagedType.U4     )] UInt32 dwEncodingType, 
            [In, MarshalAs(UnmanagedType.SysUInt)] IntPtr hCryptProv, 
            [In, MarshalAs(UnmanagedType.U4     )] UInt32 dwFlags, 
            [In, MarshalAs(UnmanagedType.SysUInt)] IntPtr pvPara
        ); 
        // добавить сертификат в хранилище
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            SetLastError = true)]
        internal static extern bool CertAddCertificateContextToStore(
            [In, MarshalAs(UnmanagedType.SysUInt)] IntPtr hCertStore, 
            [In, MarshalAs(UnmanagedType.SysUInt)] IntPtr pCertContext,
            [In, MarshalAs(UnmanagedType.U4     )] UInt32 dwAddDisposition, 
            [In, MarshalAs(UnmanagedType.SysUInt), Optional] IntPtr ppStoreContext
        );
        // удалить сертификат из хранилища
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            SetLastError = true)]
        internal static extern bool CertDeleteCertificateFromStore(
            [In, MarshalAs(UnmanagedType.SysUInt)] IntPtr pCertContext
        );
        // закрыть хранилище
        [DllImport("crypt32.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CertCloseStore(
            [In, MarshalAs(UnmanagedType.SysUInt)] IntPtr hCertStore, 
            [In, MarshalAs(UnmanagedType.U4     )] UInt32 dwFlags
        ); 
    }
}
