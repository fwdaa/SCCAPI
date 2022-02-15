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
    }
}
