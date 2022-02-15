package aladdin.iso7816.ber;
import aladdin.iso7816.*; 

///////////////////////////////////////////////////////////////////////////
// Ссылка на файл (0x51)
///////////////////////////////////////////////////////////////////////////
public class FileReference extends DataObject
{
    // короткий идентификатор
    public static FileReference fromShortID(byte id)
    {
        // проверить корректность 
        if (id < 0 || id >= 31) throw new IllegalArgumentException(); 

        // короткий идентификатор
        return new FileReference(new byte[] { (byte)(id << 3) }); 
    }
    // идентификатор 
    public static FileReference fromID(short id)
    {
        // закодировать идентификатор
        byte[] content = new byte[] { (byte)((id >>> 8) & 0xFF), (byte)id }; 

        // вернуть идентификатор
        return new FileReference(content); 
    }
    // путь (абсолютный или относительный) 
    public static FileReference fromPath(short[] path)
    {
        // выделить память для данных
        byte[] content = new byte[path.length * 2]; 

        // для всех составляющих пути
        for (int i = 0; i < path.length; i++)
        {
            // закодировать составляющую
            content[2 * i + 0] = (byte)((path[i + 1] >>> 8) & 0xFF); 
            content[2 * i + 1] = (byte)((path[i + 2]      ) & 0xFF); 
        }
        // вернуть идентификатор
        return new FileReference(content); 
    }
    // квалифицированный путь 
    public static FileReference fromQualifiedPath(short[] path, byte p1)
    {
        // выделить память для данных
        byte[] content = new byte[path.length * 2 + 1]; 

        // для всех составляющих пути
        for (int i = 0; i < path.length; i++)
        {
            // закодировать составляющую
            content[2 * i + 0] = (byte)((path[i + 1] >>> 8) & 0xFF); 
            content[2 * i + 1] = (byte)((path[i + 2]      ) & 0xFF); 
        }
        // указать значение P1 и вернуть идентификатор 
        content[path.length * 2] = p1; return new FileReference(content); 
    }
    // конструктор
    public FileReference(byte[] content) 
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.FILE_REFERENCE, content); 
    }
    // короткий идентификатор файла
    public Byte shortID() 
    {
        // проверить корректность
        if (content().length != 1) return null; 

        // вернуть короткий идентификатор
        return (byte)((content()[0] >>> 3) & 0x1F); 
    }
    // идентификатор файла
    public Short id()
    {
        // проверить корректность
        if (content().length != 2) return null; 

        // вернуть короткий идентификатор
        return (short)(((content()[0] & 0xFF) << 8) | (content()[1] & 0xFF)); 
    }
    // идентификатор файла
    public short[] path() 
    {
        // проверить наличие мастер-файла
        if (content().length == 0) return new short[] { 0x3F00 }; 
        
        // проверить корректность
        if (content().length <= 2) return null; 

        // выделить память для пути
        short[] path = new short[content().length / 2]; 

        // для всех составляющих пути
        for (int i = 0; i < path.length; i++)
        {
            // закодировать составляющую
            path[i] = (short)(((content()[2 * i + 0] & 0xFF) << 8) | (content()[2 * i + 1] & 0xFF)); 
        }
        return path; 
    }
    // значение P1
    public Integer p1() 
    {
        // проверить корректность
        if (content().length < 2 || (content().length % 1) == 0) return null; 

        // вернуть значение P1
        return (int)content()[content().length - 1]; 
    }
}
