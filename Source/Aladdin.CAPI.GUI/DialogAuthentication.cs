using System;
using System.Threading;
using System.ComponentModel;
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
    ///////////////////////////////////////////////////////////////////////////
    // Протокол аутентификации с использованием диалога
    ///////////////////////////////////////////////////////////////////////////
    public abstract class DialogAuthentication : Authentication
    {
        // выполнить аутентификацию локально
        protected abstract Credentials[] LocalAuthenticate(SecurityObject obj); 

        // выполнить аутентификацию
        public override Credentials[] Authenticate(SecurityObject obj)
        {
            // при отсутствии необходимости удаленного вызова
            if (Thread.CurrentThread.GetApartmentState() == ApartmentState.STA)
            {
                // выполнить локальное отображение диалога
                return LocalAuthenticate(obj); 
            }
            // создать удаленный клиент
            using (RemoteClient remoteClient = new RemoteClient(this, obj))
            { 
                // выполнить удаленную аутентификацию
                return (Credentials[])Proxy.Windows.WndServerWindow.Run(0x400, remoteClient); 
            }
        }
        private class RemoteClient : Remoting.RemoteClient
        {
            // используемая аутентификация и объект аутентификации
            private DialogAuthentication authentication; private SecurityObject obj; 

            // конструктор
            public RemoteClient(DialogAuthentication authentication, SecurityObject obj)
            {  
                // сохранить переданные параметры
                this.authentication = authentication; this.obj = RefObject.AddRef(obj); 
            }
            // деструктор
            protected override void OnDispose()
            {
                // освободить выделенные ресурсы
                RefObject.Release(obj); base.OnDispose();
            }
            // функция потока 
            [STAThread]
            public override void ThreadProc(Remoting.IBackgroundTask task, DoWorkEventArgs args)
            {
                // выполнить преобразование типа
                IWin32Window window = (IWin32Window)task.LocalHandler; 

                // создать прокси для объекта
                object proxy = Proxy.Windows.WndClientProxy.Create(obj, window.Handle, 0x400); 

                // выполнить локальное отображение диалога
                args.Result = authentication.LocalAuthenticate((SecurityObject)proxy); 
            }
        }
    }
}

