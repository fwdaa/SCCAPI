using System; 
using System.Runtime.InteropServices;

namespace Aladdin.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Вызов методов из внешних модулей
    ///////////////////////////////////////////////////////////////////////////
    internal static class NativeMethods    
    {        
		// стандартные оконные сообщения
		internal const int WM_MOVE	= 0x0003;
		internal const int WM_SIZE	= 0x0005;
		internal const int WM_PAINT	= 0x000F;
        internal const int WM_APP   = 0x8000; 

		// сообщения списку элементов
		internal const int LVM_FIRST					= 0x1000;
		internal const int LVM_GETHEADER				= LVM_FIRST + 31;
		internal const int LVM_SETEXTENDEDLISTVIEWSTYLE	= LVM_FIRST + 54;
		internal const int LVM_GETEXTENDEDLISTVIEWSTYLE	= LVM_FIRST + 55;
		internal const int LVM_GETCOLUMNORDERARRAY		= LVM_FIRST + 59;

		///////////////////////////////////////////////////////////////////////
		// Структура прямоугольника
		///////////////////////////////////////////////////////////////////////
		[StructLayout(LayoutKind.Sequential)]
		internal struct RECT
		{
			public int left;  public int top;
			public int right; public int bottom;
		}
		///////////////////////////////////////////////////////////////////////
		// Функции управления окнами
		///////////////////////////////////////////////////////////////////////
		[DllImport("user32.dll", CharSet = CharSet.Auto, 
			CallingConvention = CallingConvention.Winapi)]
		internal static extern bool IsWindowVisible(IntPtr hwnd);

		[DllImport("user32.dll", CharSet = CharSet.Auto, 
			CallingConvention = CallingConvention.Winapi)]
		internal static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);

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
    }
}
