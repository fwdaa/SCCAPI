package aladdin;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Объект со счетчиком ссылок
///////////////////////////////////////////////////////////////////////////////
public class RefObject implements IRefObject
{
    public final boolean REFOBJECT_CHECK = false; 
    
    // увеличить счетчик ссылок
    public static <T extends IRefObject> T addRef(T obj) 
    { 
        // увеличить счетчик ссылок
        if (obj != null) obj.addRef(); return obj; 
    }
    // уменьшить счетчик ссылок
    public static void release(IRefObject obj) throws IOException
    { 
        // уменьшить счетчик ссылок
        if (obj != null) obj.release(); 
    }
    // счетчик ссылок и стек вызова
    private int refs; private final String[] stackTrace; 
    
    // признак освобождения
    private boolean disposed; 
         
    // конструктор
    public RefObject() { this.refs = 1; this.disposed = false; 
        
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
        try { if (!disposed) dispose(false); } finally { super.finalize(); }
    }    
    // уменьшить счетчик ссылок
    @Override public void close() throws IOException { release(); }
    
    // увеличить счетчик ссылок
    @Override public final void addRef() { refs++; } 
    
    // уменьшить счетчик ссылок
    @Override public void release() throws IOException
    {  
        // освободить выделенные ресурсы
        if (refs > 1) --refs; else dispose(true); 
    }
    // освободить выделенные ресурсы
    protected void dispose(boolean disposing) throws IOException
    {
        // освободить выделенные ресурсы
        if (disposing) { try { onClose(); } finally { --refs; disposed = true; }}
        
        // при необходимости трассировки
        if (REFOBJECT_CHECK && (!disposing || refs != 0))
        {
            // вывести сообщение об ошибке
            System.out.println(String.format("Class = %1$s, Refs = %2$d", getClass(), refs));

            // вывести стек ошибки
            System.out.println(StackTrace.toString(stackTrace)); 
        }
    }
    // освободить выделенные ресурсы
    protected void onClose() throws IOException {}
}
