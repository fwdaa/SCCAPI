package aladdin.iso7816;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Зашифрованные данные с указанием типа
///////////////////////////////////////////////////////////////////////////////
public class Cryptogram 
{
    // конструктор
    public Cryptogram(byte[] content) throws IOException
    {
        // проверить размер данных
        if (content.length == 0) throw new IOException(); 
        
        // выделить память для данных
        type = content[0]; data = new byte[content.length - 1]; 
        
        // скопировать данные
        System.arraycopy(content, 1, data, 0, data.length);
    }
    // конструктор
    public Cryptogram(byte type, byte[] data)
    {
        // сохранить переданные параметры
        this.type = type; this.data = data; 
    }
    // тип и зашифрованные данные
    public final byte type; public final byte[] data; 
    
    // закодированное представление
    public final byte[] encoded()
    {
        // выделить память для содержимого 
        byte[] encoded = new byte[1 + data.length]; encoded[0] = type;
        
        // скопировать тип и зашифрованные данные
        System.arraycopy(data, 0, encoded, 1, data.length); return encoded; 
    }
}
