package aladdin;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Объект со счетчиком ссылок
///////////////////////////////////////////////////////////////////////////////
public interface IRefObject extends Closeable
{
    // увеличить/уменьшить счетчик ссылок 
    public void addRef(); public void release() throws IOException; 
    
    // уменьшить счетчик ссылок
    @Override public void close() throws IOException; 
}
