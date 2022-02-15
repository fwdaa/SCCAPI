using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.Proxy.Windows
{
    ///////////////////////////////////////////////////////////////////////////
    // Прокси для передачи сообщений окну
    ///////////////////////////////////////////////////////////////////////////
#if !(NETSTANDARD || NETCOREAPP)
    [SecurityCritical]
    public sealed class WndClientProxy : DynamicProxy
    {
        // создать прозрачный прокси
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]		
        public static T Create<T>(T obj, IntPtr hwnd, int msg) where T : class
        {
            // указать тип для прокси
            Type type = (obj is MarshalByRefObject) ? obj.GetType() : typeof(T); 

            // создать реальный прокси
            WndClientProxy proxy = new WndClientProxy(obj, type, hwnd, msg); 

            // вернуть прозрачный прокси
            return (T)proxy.GetTransparentProxy(); 
        }
        // конструктор
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]		
        private WndClientProxy(object obj, Type type, IntPtr hwnd, int msg) : base(obj, type) 
        { 
            // связать прокси с объектом
            this.hwnd = hwnd; this.msg = msg; 
        }
        // выполнить метод объекта
        [SecuritySafeCritical] 
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        public System.Runtime.Remoting.Messaging.IMessage ProcessInvoke(
            System.Runtime.Remoting.Messaging.IMessage message)
        {
            // обработать вызов метода
            return base.Invoke(message); 
        }
        // обработать вызов метода
        [SecurityCritical] 
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        public override System.Runtime.Remoting.Messaging.IMessage Invoke(
            System.Runtime.Remoting.Messaging.IMessage message)
        {
            // выполнить преобразование типа
            System.Runtime.Remoting.Messaging.IMethodCallMessage call = 
                (System.Runtime.Remoting.Messaging.IMethodCallMessage)message; 

            // заблокировать данные
            GCHandle wParam = GCHandle.Alloc(Target); 
            GCHandle lParam = GCHandle.Alloc(call  ); 

            // передать сообщение
            IntPtr ptr = NativeMethods.SendMessage(hwnd, msg, 
                GCHandle.ToIntPtr(wParam), GCHandle.ToIntPtr(lParam)
            ); 
            // заблокировать данные
            GCHandle rParam = GCHandle.FromIntPtr(ptr); 

            // извлечь результат
            System.Runtime.Remoting.Messaging.IMethodReturnMessage result = 
                (System.Runtime.Remoting.Messaging.IMethodReturnMessage)rParam.Target; 

            // разблокировать объекты
            wParam.Free(); lParam.Free(); rParam.Free(); return result; 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Переопределенная оконная процедура
        ///////////////////////////////////////////////////////////////////////////
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public static void WndProc(ref System.Windows.Forms.Message message)
        {
            // преобразовать тип данных
            GCHandle wParam = GCHandle.FromIntPtr(message.WParam); 
            GCHandle lParam = GCHandle.FromIntPtr(message.LParam); 

            // извлечь объект и параметры вызова
            MarshalByRefObject obj  = (MarshalByRefObject)wParam.Target; 

            // извлечь параметры вызова
            System.Runtime.Remoting.Messaging.IMessage call = 
                (System.Runtime.Remoting.Messaging.IMessage)lParam.Target; 

            // создать обработчик
            WndClientProxy handler = new WndClientProxy(
                obj, obj.GetType(), message.HWnd, message.Msg
            ); 
            // обработать сообщение
            System.Runtime.Remoting.Messaging.IMessage result = handler.ProcessInvoke(call); 

            // заблокировать и вернуть результат
            message.Result = GCHandle.ToIntPtr(GCHandle.Alloc(result)); 
        }
#else 
    [SecurityCritical]
    public sealed class WndClientProxy : DynamicProxy
    {
        // создать прозрачный прокси
        public static TClass Create<TClass>(TClass obj, IntPtr hwnd, int msg) where TClass : class
        {
            // создать прокси защищенного объекта
            WndClientProxy interceptor = new WndClientProxy(hwnd, msg); 

            // вернуть прозрачный прокcи
            return interceptor.GetTransparentProxy(obj); 
        }
        // конструктор
        public WndClientProxy(IntPtr hwnd, int msg) {  this.hwnd = hwnd; this.msg = msg; }

        // выполнить метод объекта
        public void ProcessIntercept(Castle.DynamicProxy.IInvocation invocation)
        {
            // обработать вызов метода
            base.Intercept(invocation); 
        }
        // обработать вызов метода
        [SecurityCritical] 
        public override void Intercept(Castle.DynamicProxy.IInvocation invocation)
        {
            // заблокировать данные
            GCHandle wParam = GCHandle.Alloc(invocation.InvocationTarget); 
            GCHandle lParam = GCHandle.Alloc(invocation); 

            // передать сообщение
            NativeMethods.SendMessage(hwnd, msg, 
                GCHandle.ToIntPtr(wParam), GCHandle.ToIntPtr(lParam)
            ); 
            // разблокировать объекты
            wParam.Free(); lParam.Free(); 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Переопределенная оконная процедура
        ///////////////////////////////////////////////////////////////////////////
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public static void WndProc(ref System.Windows.Forms.Message message)
        {
            // преобразовать тип данных
            GCHandle lParam = GCHandle.FromIntPtr(message.LParam); 

            // извлечь параметры вызова
            Castle.DynamicProxy.IInvocation invocation = (Castle.DynamicProxy.IInvocation)lParam.Target; 

            // создать обработчик
            WndClientProxy handler = new WndClientProxy(message.HWnd, message.Msg); 

            // обработать сообщение
            handler.ProcessIntercept(invocation); message.Result = IntPtr.Zero; 
        }
#endif 
        // преобразовать тип выходного параметра
        [SecurityCritical] 
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        protected override object ConvertOutObject(MarshalByRefObject value)
        {
            // создать прокси-объект для удаленного потока
            return Create(value, hwnd, msg); 
        }
        // описатель окна и идентификатор сообщения
        private IntPtr hwnd; private int msg; 
    }
}
