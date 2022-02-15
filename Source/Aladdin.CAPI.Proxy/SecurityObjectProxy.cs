using System;
using System.Reflection;
using System.Security; 
using System.Security.Permissions; 

namespace Aladdin.CAPI.Proxy
{
    ///////////////////////////////////////////////////////////////////////////
    // Прокси защищенного объекта
    ///////////////////////////////////////////////////////////////////////////
#if !(NETSTANDARD || NETCOREAPP)
    [SecurityCritical]
    public sealed class SecurityObjectProxy : DynamicProxy
    {
        // защищенный объект для аутентификации
        private SecurityObject secObj; 

        // создать прозрачный прокси
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        public static SecurityObject Create(SecurityObject obj)
        {
            // создать прокси защищенного объекта
            SecurityObjectProxy proxy = new SecurityObjectProxy(obj, obj.GetType(), obj); 

            // вернуть прозрачный прокcи
            return (SecurityObject)proxy.GetTransparentProxy(); 
        }
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        public static T Create<T>(T obj, SecurityObject secObj) where T : class
        {
            // указать тип для прокси
            Type type = (obj is MarshalByRefObject) ? obj.GetType() : typeof(T); 

            // создать реальный прокси
            SecurityObjectProxy proxy = new SecurityObjectProxy(obj, type, secObj); 

            // вернуть прозрачный прокси
            return (T)proxy.GetTransparentProxy(); 
        }
        // конструктор
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        private SecurityObjectProxy(object obj, Type type, SecurityObject secObj) 
            
            // сохранить переданные параметры
            : base(obj, type) { this.secObj = secObj; }

        // выполнить метод объекта
        [SecurityCritical]
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        protected override object Invoke(MethodInfo methodInfo, object[] args)
        {
            // вызвать метод
            try { return base.Invoke(methodInfo, args); } catch (Exception e) 
            { 
                // проверить тип исключения
                if (!secObj.IsAuthenticationRequired(e)) throw; 

                // выполнить аутентификацию и вызвать метод
                secObj.Authenticate(); return base.Invoke(methodInfo, args);
            }
        }
#else 
    [SecurityCritical]
    public sealed class SecurityObjectProxy : DynamicProxy
    {
        // создать прозрачный прокси
        public static SecurityObject Create(SecurityObject obj) { return Create(obj, obj); }

        // создать прозрачный прокси
        private static T Create<T>(T obj, SecurityObject secObj) where T : class
        {
            // создать прокси защищенного объекта
            SecurityObjectProxy interceptor = new SecurityObjectProxy(secObj); 

            // вернуть прозрачный прокcи
            return interceptor.GetTransparentProxy<T>(obj); 
        }
        // конструктор
        private SecurityObjectProxy(SecurityObject secObj) 
            
            // сохранить переданные параметры
            { this.secObj = secObj; } private SecurityObject secObj; 

        // выполнить метод объекта
        [SecurityCritical]
        public override void Intercept(Castle.DynamicProxy.IInvocation invocation)
        {
            // вызвать метод
            try { base.Intercept(invocation); } catch (Exception e) 
            { 
                // проверить тип исключения
                if (!secObj.IsAuthenticationRequired(e)) throw; 

                // выполнить аутентификацию и вызвать метод
                secObj.Authenticate(); base.Intercept(invocation);
            }
        }
#endif 
        // преобразовать тип выходного параметра
        [SecurityCritical]
        [SecurityPermission(SecurityAction.Demand, Infrastructure = true)]
        protected override object ConvertOutObject(MarshalByRefObject value)
        {
            // получить атрибуты типа
            object[] attributes = value.GetType().GetCustomAttributes(
                typeof(SecurityObjectAttribute), true
            );
            // проверить наличие атрибута
            if (attributes.Length == 0) return value;

            // преобразовать тип атрибута
            SecurityObjectAttribute attribute = (SecurityObjectAttribute)attributes[0]; 

            // вернуть прокси защищенного объекта
            return Create(value, attribute.GetObject(value)); 
        }
    }
}
