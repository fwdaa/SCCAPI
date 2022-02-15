using System;

namespace Aladdin.PCSC.Windows
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры отображения диалога выбора смарт-карты
    ///////////////////////////////////////////////////////////////////////////
    public class SelectParams
    {
        // конструктор
        public SelectParams(IntPtr hwnd, IntPtr hicon, string title, string search)
        {
            // сохранить переданные параметры
            HWnd = hwnd; HIcon = hicon; Title = title; Search = search; 
        }
        public readonly IntPtr HWnd;    // описатель родительского окна
        public readonly IntPtr HIcon;   // описатель иконки диалога
        public readonly String Title;   // заголовок диалога
        public readonly String Search;  // строка выбора смарт-карты
    }
}
