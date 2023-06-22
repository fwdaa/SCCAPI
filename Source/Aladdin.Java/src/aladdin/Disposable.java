package aladdin;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Освобождаемый объект
///////////////////////////////////////////////////////////////////////////////
public class Disposable implements Closeable
{
    public final boolean REFOBJECT_CHECK = false; 
    
    // признак освобождения и стек вызова
    private boolean disposed; private final String[] stackTrace; 
         
    // конструктор
    public Disposable() { this.disposed = false; 
        
        // инициализировать переменную
        if (!REFOBJECT_CHECK) stackTrace = null; 
         
        // выбросить исключение
        else try { throw new Exception(""); } catch (Throwable e)
        {
            // получить стек исключения в виде строки
            stackTrace = StackTrace.fromException(e); 
        }
    } 
    // деструктор
    @Override protected void finalize() throws Throwable 
    {
        // освободить выделенные ресурсы
        if (!disposed) dispose(false); super.finalize(); 
    }    
    // освободить выделенные ресурсы
    @Override public void close() throws IOException { dispose(true); }
    
    // освободить выделенные ресурсы
    protected void dispose(boolean disposing) throws IOException
    {
        // освободить выделенные ресурсы
        if (disposing) { onClose(); disposed = true; }
        
        // при необходимости трассировки
        else if (stackTrace != null && stackTrace.length != 0)
        {
            // вывести сообщение об ошибке
            System.out.println(String.format("Class = %1$s", getClass()));

            // вывести стек ошибки
            System.out.println(StackTrace.toString(stackTrace)); 
        }
    }
    // освободить выделенные ресурсы
    protected void onClose() throws IOException {}
}
