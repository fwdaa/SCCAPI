package aladdin.iso7816;
import aladdin.iso7816.ber.*; 
import aladdin.asn1.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Элементарный файл
///////////////////////////////////////////////////////////////////////////////
public abstract class ElementaryFile extends File
{
    // конструктор
    protected ElementaryFile(DedicatedFile parent, short id) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, id, new FileControlInformation()); this.shortID = null;
    }
    // конструктор
    protected ElementaryFile(DedicatedFile parent, byte shortID) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, null, new FileControlInformation()); this.shortID = shortID;
    }
    // конструктор
    protected ElementaryFile(DedicatedFile parent, 
        Short id, Byte shortID, FileControlInformation info) throws IOException
    { 
        // сохранить переданные параметры
        super(parent, id, info); this.shortID = shortID; 
    }
    // сокращенный идентификатор файла
    public final Byte shortID() { return shortID; } private final Byte shortID;
    
    // выделить родительский каталог
    @Override public DedicatedFile selectParent(LogicalChannel channel) throws IOException
    {
        return parent(); 
    }
    // категория файла
    @Override public final int fileCategory()
    {
        // получить дескриптор файла
        DataObject[] objs = info().get(Tag.context(0x02, PC.PRIMITIVE)); 
            
        // проверить наличие дескриптора
        if (objs.length == 0) return FileCategory.UNKNOWN; 

        // получить содержимое
        byte[] content = objs[0].content(); 
        
        // проверить размер содержимого
        if (content.length < 1 || (content[0] & 0x80) != 0)
        {
            // указать значение по умолчанию
            return FileCategory.UNKNOWN; 
        }
        // получить возможность разделения
        int shareable = ((content[0] & 0x40) != 0) ? FileCategory.SHAREABLE : 0; 
        
        // в зависимости установленных битов
        switch ((content[0] >>> 3) & 0x7)
        {
        case 0x0: return FileCategory.WORKING  | shareable; 
        case 0x1: return FileCategory.INTERNAL | shareable; 
        case 0x7: break; 

        // вернуть категорию файла
        default: return (((content[0] >>> 3) & 0x7) + 1) | shareable; 
        }
        // категория файла неизвестна
        return FileCategory.UNKNOWN; 
    }
    // общий размер байтов
    public final java.lang.Integer contentSize() throws IOException
    {
        // найти объект
        DataObject[] objs = info().get(Tag.context(0x00, PC.PRIMITIVE)); if (objs.length == 0) return null; 

        // проверить размер содержимого
        byte[] content = objs[0].content(); if (content.length > 4) return java.lang.Integer.MAX_VALUE; 
        
        // для всех байтов размера
        int value = 0; for (byte next : content) value = (value << 8) | (next & 0xFF); 
        
        // вернуть размер файла
        return (value >= 0) ? value : java.lang.Integer.MAX_VALUE; 
    }
    // прочитать содержимое файла
    public abstract Response readContent(LogicalChannel channel, 
        int secureType, SecureClient secureClient) throws IOException; 
}
