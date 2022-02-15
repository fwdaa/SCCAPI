using System;
using System.ComponentModel;
using System.Windows.Forms;
using System.Security;
using System.Security.Permissions;

namespace Aladdin.CAPI.Proxy.Windows
{
    ///////////////////////////////////////////////////////////////////////////
    // Скрытое окно сервера обработки сообщений
    ///////////////////////////////////////////////////////////////////////////
    public sealed class WndServerWindow : Form, Remoting.IBackgroundHandler
    {
        // идентификатор сообщения и результат выполнения 
        private int msg; private RunWorkerCompletedEventArgs result;

        // конструктор
        public WndServerWindow(int msg) 
        { 
            // сохранить переданные параметры
            this.msg = msg; result = null; InitializeComponent();

            // установить свойства окна
            ShowInTaskbar = false; Visible = false; Enabled = false; 
        }
        private void InitializeComponent()
        {
            // инициализировать окно
            this.SuspendLayout(); this.ResumeLayout(false);
        }
        // установить свойства описателя окна
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        protected override void OnHandleCreated(EventArgs e)
        {
            // вызвать базовую функцию
            base.OnHandleCreated(e);

            // сделать окном только приема сообщений
            NativeMethods.SetParent(Handle, new IntPtr(-3));
        }
        // переопределенная оконная процедура
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		protected override void WndProc(ref Message message)
        {
	        // вызвать базовую функцию
	        base.WndProc(ref message); if (message.Msg != msg) return;

            // обработать сообщение
            WndClientProxy.WndProc(ref message); 
        }
        // обработка уведомлений о прогрессе 
        public void OnProgressChanged(object sender, ProgressChangedEventArgs e) {} 
        // обработчик завершения 
        public void OnCompleted(object sender, RunWorkerCompletedEventArgs args)
        {
            // сохранить результат
            result = args; Close(); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Создать цикл обработки и запустить удаленный поток
        ///////////////////////////////////////////////////////////////////////
        public static object Run(int msg, Remoting.RemoteClient client)
        {
            // создать окно
            using (WndServerWindow window = new WndServerWindow(msg)) 
            { 
                // запустить поток
                using (Remoting.RemoteClientControl control = client.Start(window))
                { 
                    // обработать сообщения
                    Application.Run(window); 
                
                    // проверить отсутствие исключений
                    if (window.result.Error != null) throw window.result.Error; 
                
                    // вернуть результат
                    return window.result.Result; 
                }
            }
        }
    }
}
