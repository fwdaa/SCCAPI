package aladdin.iso7816;
import aladdin.asn1.*; 
import aladdin.util.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////
// Объект данных COMPACT-TLV
///////////////////////////////////////////////////////////////////////
public class CompactTLV
{
    // закодировать объекты
    public static byte[] encode(CompactTLV[] objects)
    {
        // выделить память для закодированных представлений
        byte[][] encodeds = new byte[objects.length][];  

        // получить закодированные представления
        for (int i = 0; i < objects.length; i++) encodeds[i] = objects[i].encoded();

        // объединить закодированные представления
        return Array.concat(encodeds); 
    }
    // раскодировать объекты
    public static CompactTLV[] decode(byte[] content) throws IOException
    {
        // создать пустой список объектов
        List<CompactTLV> objects = new ArrayList<CompactTLV>(); 

        // для всех внутренних объектов
        for (int offset = 0; offset < content.length; )
        { 
            // раскодировать содержимое
            CompactTLV obj = new CompactTLV(content, offset, content.length - offset); 

            // перейти на следующий объект
            objects.add(obj); offset += obj.encoded().length; 
        }
        // вернуть раскодированные объекты
        return objects.toArray(new CompactTLV[objects.size()]); 
    }
    // тип и значение
    private final int tag; private final byte[] value; 

    // конструктор
    public CompactTLV(Tag tag, byte[] content) 
    { 
        // проверить корректность заголовка
        if (!tag.asnTag.tagClass.equals(TagClass.APPLICATION)) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException();
        }
        // проверить корректность заголовка и размера
        if (tag.asnTag.value > 0xF) throw new IllegalArgumentException();

        // проверить корректность размера
        if (content.length > 0xF) throw new IllegalArgumentException();

        // сохранить переданные значения
        this.tag = tag.asnTag.value; this.value = content; 
    }
    // раскодировать данные
    public CompactTLV(byte[] encoded, int offset, int length) throws IOException
    {
        // проверить корректность размера
        if (length < 1) throw new IOException(); 

        // извлечь тип и размер данных 
        tag = (encoded[offset] >>> 4) & 0x0F; int cb = encoded[offset] & 0x0F;
            
        // проверить размер данных
        if (length < 1 + cb) throw new IOException(); 

        // скопировать данные
        value = new byte[cb]; System.arraycopy(encoded, offset + 1, value, 0, cb); 
    }
    // значение типа
    public final Tag tag() { return Tag.application(tag, PC.PRIMITIVE); }

    // содержимое объекта
    public final byte[] value() { return value; }

    // получить закодированное представление
    public final byte[] encoded() 
    { 
        // выделить память для представления
        byte[] encoded = new byte[1 + value.length]; 

        // указать заголовок и размер
        encoded[0] = (byte) ((tag << 4) | value.length); 

        // скопировать данные
        System.arraycopy(value, 0, encoded, 1, value.length); return encoded;
    }
    // выполнить преобразование типа
    public final DataObject toObject() { return new DataObject(this); }
}
