package aladdin.capi.proxy;
import java.lang.reflect.*; 

///////////////////////////////////////////////////////////////////////////////
// Proxy-обработчик 
///////////////////////////////////////////////////////////////////////////////
public class DynamicProxy implements InvocationHandler
{
    // шаблон создания прокси
    private static Object create(Object target, Class<?>[] interfaces, Object... parameters)
    {
        // указать загрузчик классов
        ClassLoader classLoader = target.getClass().getClassLoader(); 
        
        // создать реальный прокси
        DynamicProxy proxy = new DynamicProxy(target/*, parameters*/); 
        
        // вернуть прозрачный прокси
        return Proxy.newProxyInstance(classLoader, interfaces, proxy); 
    }
    // конструктор
    protected DynamicProxy(Object target)

        // сохранить переданные параметры
        { this.target = target; } private final Object target; 

    // защищаемый объект
    public Object target() { return target; }

    // вызвать метод
    @Override public Object invoke(Object proxy, Method methodInfo, Object[] args) throws Throwable 
    {
        // вызвать метод
        return invoke(methodInfo, args); 
    }
    // вызвать метод
    protected Object invoke(Method methodInfo, Object[] args) throws Throwable 
    {
        try {  
            // вызвать метод
            Object result = methodInfo.invoke(target, args); 

            // преобразовать значение
            return (result != null) ? convertOutObject(result) : result; 
        }
        // обработать возможную ошибку
        catch (InvocationTargetException exception) { throw exception.getTargetException(); }
    }
    // преобразовать тип выходного параметра
    protected Object convertOutObject(Object value) throws Throwable { return value; } 
}
