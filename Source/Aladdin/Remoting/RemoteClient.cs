using System;
using System.Threading;
using System.Reflection;
using System.ComponentModel;

namespace Aladdin.Remoting
{
    ///////////////////////////////////////////////////////////////////////////
    // Удаленный поток
    ///////////////////////////////////////////////////////////////////////////
    public abstract class RemoteClient : RefObject
    {
        // создать объект управления потоком клиента
        public RemoteClientControl Start(IBackgroundHandler handler)
        {
            // получить тип апартаментов
            ApartmentState apartmentState = GetApartmentState(); 

            // для многопоточных апартаментов
            if (apartmentState == ApartmentState.MTA)
            { 
                // создать объект управления потоком
                using (IBackgroundTask task = new BackgroundWorker(this, handler))  
                {  
                    // создать объект управления потоком
                    using (RemoteClientControl control = CreateRemoteControl(task)) 
                    {  
                        // запустить поток
                        control.Start(); return RefObject.AddRef(control); 
                    }
                }
            }
            else { 
                // создать объект потока
                using (IBackgroundTask task = new BackgroundThread(this, apartmentState, handler)) 
                {  
                    // создать объект управления потоком
                    using (RemoteClientControl control = CreateRemoteControl(task)) 
                    {  
                        // запустить поток
                        control.Start(); return RefObject.AddRef(control); 
                    }
                }
            }
        }
        // тип апартаментов потока
        protected virtual ApartmentState GetApartmentState()
        {
            // указать тип метода
            BindingFlags bindingFlags = BindingFlags.InvokeMethod |  
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic; 

            // указать тип параметров метода
            Type[] types = new Type[] { typeof(IBackgroundTask), typeof(DoWorkEventArgs) }; 

            // получить информацию метода
            MethodInfo method = GetType().GetMethod("ThreadProc", bindingFlags, null, types, null); 

            // получить атрибуты метода
            object[] attributes = method.GetCustomAttributes(typeof(MTAThreadAttribute), true); 

            // проверить атрибуты метода
            if (attributes.Length > 0) return ApartmentState.MTA;

            // получить атрибуты метода
            attributes = method.GetCustomAttributes(typeof(STAThreadAttribute), true); 

            // проверить атрибуты метода
            if (attributes.Length > 0) return ApartmentState.STA; 
            
            // неизвестный тип апартаментов
            return ApartmentState.Unknown;
        }
        // создать объект управления потоком клиента
        protected virtual RemoteClientControl CreateRemoteControl(IBackgroundTask task)
        {
            // создать объект управления потоком клиента
            return new RemoteClientControl(task); 
        }
        // функция удаленного потока 
        public abstract void ThreadProc(IBackgroundTask task, DoWorkEventArgs args); 
    }
}
