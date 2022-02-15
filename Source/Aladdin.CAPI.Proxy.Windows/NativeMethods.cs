using System; 
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.Proxy.Windows
{
    ///////////////////////////////////////////////////////////////////////////
    // Вызов методов из внешних модулей
    ///////////////////////////////////////////////////////////////////////////
    internal static class NativeMethods    
    {        
        // синхронная передача сообщений
 		[DllImport("user32.dll", CharSet = CharSet.Auto, 
            CallingConvention = CallingConvention.Winapi)]
		internal static extern IntPtr SendMessage(
            IntPtr hwnd, Int32 msg, IntPtr wParam, IntPtr lParam
        );
        // ассинхронная передача сообщений
 		[DllImport("user32.dll", CharSet = CharSet.Auto, 
            CallingConvention = CallingConvention.Winapi)]
		internal static extern bool PostMessage(
            IntPtr hwnd, Int32 msg, IntPtr wParam, IntPtr lParam
        );
        [DllImport("user32.dll", CharSet = CharSet.Auto, 
            CallingConvention = CallingConvention.Winapi)]
        internal static extern IntPtr SetParent(IntPtr hwnd, IntPtr hParent);
    }
}
