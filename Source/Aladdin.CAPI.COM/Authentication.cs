using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;

namespace Aladdin.CAPI.COM
{
    ///////////////////////////////////////////////////////////////////////////
    // Способ аутентификации
    ///////////////////////////////////////////////////////////////////////////
    [ClassInterface(ClassInterfaceType.None)]
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class Authentication : IAuthentication
    {
        // способ аутентификации
        public readonly AuthenticationSelector Selector; 

        // конструктор
        public Authentication(IWin32Window window)
        {
            // сохранить переданные параметры
            Selector = new GUI.AuthenticationSelector(window, "USER"); 
        }
        // конструктор
        public Authentication(string password)
        {
            // сохранить переданные параметры
            Selector = new Auth.PasswordSelector("USER", password);
        }
    }
}
