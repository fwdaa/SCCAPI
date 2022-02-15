using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security;
using System.Security.Permissions;

namespace Aladdin.CAPI.Proxy
{
    ///////////////////////////////////////////////////////////////////////////
    // Proxy-обработчик 
    ///////////////////////////////////////////////////////////////////////////
#if !(NETSTANDARD || NETCOREAPP)
    [SecurityCritical]
    public class DynamicProxy : System.Runtime.Remoting.Proxies.RealProxy
    {
        // конструктор
        [SecurityCritical]
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        public DynamicProxy(MarshalByRefObject target) : this(target, target.GetType()) {}

        // конструктор
        [SecurityCritical]
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        public DynamicProxy(object target, Type type) : base(type) 

            // сохранить переданные параметры
            { this.target = target; } private object target; 

        // защищаемый объект
        public object Target { get { return target; }}

        // выполнить метод объекта
        [SecurityCritical]
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        public override System.Runtime.Remoting.Messaging.IMessage Invoke(
            System.Runtime.Remoting.Messaging.IMessage msg)
        {
            // выполнить преобразование типа
            System.Runtime.Remoting.Messaging.IMethodCallMessage methodCall = 
                (System.Runtime.Remoting.Messaging.IMethodCallMessage)msg; 

            // извлечь информацию о вызываемом методе
            MethodInfo methodInfo = (MethodInfo)methodCall.MethodBase; 

            // получить список параметров метода
            ParameterInfo[] parametersInfo = methodInfo.GetParameters(); 

            // скопировать параметры
            object[] args = (object[])methodCall.Args.Clone();
            try {  
                // вызвать метод
                object result = Invoke(methodInfo, args); 

                // создать список выходных параметров
                List<Object> outArgs = new List<Object>(); 

                // для всех параметров метода
                for (int i = 0; i < parametersInfo.Length; i++)
                {
                    // добавить выходной параметр
                    if (parametersInfo[i].IsOut) outArgs.Add(args[i]);
                }
                // создать ответное сообщение
                return new System.Runtime.Remoting.Messaging.ReturnMessage(
                    result, outArgs.ToArray(), outArgs.Count, 
                    methodCall.LogicalCallContext, methodCall
                ); 
            }
            // обработать возможную ошибку
            catch (Exception exception) 
            { 
                // создать ответное сообщение
                return new System.Runtime.Remoting.Messaging.ReturnMessage(
                    exception, methodCall
                ); 
            }
        }
        // выполнить метод объекта
        protected virtual object Invoke(MethodInfo methodInfo, object[] args)
        {
            // получить список параметров метода
            ParameterInfo[] parametersInfo = methodInfo.GetParameters(); 
            try {  
                // вызвать метод
                object result = methodInfo.Invoke(Target, args); 

                // при наличии значения
                if (result != null && result is MarshalByRefObject)
                {
                    // преобразовать значение
                    result = ConvertOutObject((MarshalByRefObject)result); 
                }
                // для всех параметров метода
                for (int i = 0; i < parametersInfo.Length; i++)
                {
                    // проверить наличие выходного параметра
                    if (!parametersInfo[i].IsOut) continue; 
                    
                    // при наличии значения
                    if (args[i] != null && args[i] is MarshalByRefObject)
                    {
                        // преобразовать значение
                        args[i] = ConvertOutObject((MarshalByRefObject)args[i]); 
                    }
                }
                return result; 
            }
            // обработать возможную ошибку
            catch (TargetInvocationException exception) { throw exception.InnerException; }
        }
#else 
    [SecurityCritical]
    public class DynamicProxy : Castle.DynamicProxy.IInterceptor
    {
        // создать прозрачный прокси
        public T GetTransparentProxy<T>(T target) where T : class 
        {
            // создать генератор прокси
            Castle.DynamicProxy.ProxyGenerator generator = new Castle.DynamicProxy.ProxyGenerator();

            // в зависимости от типа
            if (typeof(T).IsInterface)
            {
                // вернуть прозрачный прокcи
                return generator.CreateInterfaceProxyWithTarget(target, this); 
            }
            // вернуть прозрачный прокcи
            else return generator.CreateClassProxyWithTarget(target, this); 
        }
        // выполнить метод объекта
        [SecurityCritical]
        public virtual void Intercept(Castle.DynamicProxy.IInvocation invocation)
        {
            // получить список параметров метода
            ParameterInfo[] parametersInfo = invocation.GetConcreteMethod().GetParameters(); 
            try {  
                // вызвать метод
                invocation.Proceed(); object result = invocation.ReturnValue; 

                // при наличии значения
                if (result != null && result is MarshalByRefObject)
                {
                    // преобразовать значение
                    invocation.ReturnValue = ConvertOutObject((MarshalByRefObject)result); 
                }
                // для всех параметров метода
                for (int i = 0; i < parametersInfo.Length; i++)
                {
                    // проверить наличие выходного параметра
                    if (!parametersInfo[i].IsOut) continue; 

                    // получить значение аргумента
                    object arg = invocation.GetArgumentValue(i); 
                    
                    // при наличии значения
                    if (arg != null && arg is MarshalByRefObject)
                    {
                        // преобразовать значение
                        invocation.SetArgumentValue(i, ConvertOutObject((MarshalByRefObject)arg)); 
                    }
                }
            }
            // обработать возможную ошибку
            catch (TargetInvocationException exception) { throw exception.InnerException; }
        }
#endif 
        // преобразовать тип выходного параметра
        protected virtual object ConvertOutObject(MarshalByRefObject value) { return value; } 
    }
}
