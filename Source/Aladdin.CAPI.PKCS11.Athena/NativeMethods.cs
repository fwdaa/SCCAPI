using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;
using Aladdin.PKCS11;

namespace Aladdin.CAPI.PKCS11.Athena
{
    ///////////////////////////////////////////////////////////////////////////
    // Вызов методов из внешних модулей
    ///////////////////////////////////////////////////////////////////////////
    internal static class NativeMethods    
    {        
        // функция получения списка функций
	    [DllImport("asepkcs.dll", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Auto, ExactSpelling = true)]
	    private static extern UInt32 C_GetFunctionList([Out] out IntPtr ppFunctionList);

        // Интерфейс PKCS11
	    public class NativeAPI : Aladdin.PKCS11.API
        {
            // получить список функций
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		    public override API.CK_GETFUNCTIONLIST GetFunctionList()
		    {
			    // получить список функций
			    return new API.CK_GETFUNCTIONLIST(C_GetFunctionList); 
		    }
        };
    }
}
