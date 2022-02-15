using System;
using System.Windows.Forms; 

namespace Aladdin.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Отображение модальных окон
    ///////////////////////////////////////////////////////////////////////////
    public static class ModalView
    {
        // отобразить модальное окно
        public static DialogResult Show(IWin32Window window, Form form)
        {
            // отобразить диалог
            if (window != null && window.Handle != IntPtr.Zero) return form.ShowDialog(window); 

            // отобразить диалог на переднем плане
            else { form.TopMost = true; return form.ShowDialog(); }
        }
        // отобразить модальное окно
        public static DialogResult Show(IntPtr hwnd, Form form)
        {
            // отобразить диалог
            if (hwnd == IntPtr.Zero) { form.TopMost = true; return form.ShowDialog(); }
            
            // получить элемент управления
            IWin32Window window = Control.FromHandle(hwnd); 

            // получить окно 
            if (window == null) window = Win32Window.FromHandle(hwnd); 

            // отобразить диалог
            return form.ShowDialog(window); 
        }
    }
}
