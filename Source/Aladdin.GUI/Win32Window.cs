﻿using System;
using System.Windows.Forms;

namespace Aladdin.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Окно, связанное с описателем
    ///////////////////////////////////////////////////////////////////////////
    public class Win32Window : IWin32Window
    {
        // конструктор
        public static Win32Window FromHandle(IntPtr hwnd)
        {
            // создать объект окна
            return (hwnd != IntPtr.Zero) ? new Win32Window(hwnd) : null; 
        }
        // конструктор
        public Win32Window(IntPtr hwnd) 
        
            // сохранить переданные параметры
            { this.hwnd = hwnd; } private IntPtr hwnd;

        // описатель окна
        public IntPtr Handle { get { return hwnd; }}
    }
}