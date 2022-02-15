package aladdin.iso7816;
import aladdin.util.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////
// Объект данных SIMPLE-TLV
///////////////////////////////////////////////////////////////////////
public class SimpleTLV
{
    // закодировать объекты
    public static byte[] encode(SimpleTLV[] objects)
    {
        // выделить память для закодированных представлений
        byte[][] encodeds = new byte[objects.length][];  

        // получить закодированные представления
        for (int i = 0; i < objects.length; i++) encodeds[i] = objects[i].encoded();

        // объединить закодированные представления
        return Array.concat(encodeds); 
    }
    // раскодировать объекты
    public static SimpleTLV[] decode(byte[] content) throws IOException
    {
        // создать пустой список объектов
        List<SimpleTLV> objects = new ArrayList<SimpleTLV>(); 

        // для всех внутренних объектов
        for (int offset = 0; offset < content.length; )
        { 
            // раскодировать содержимое
            SimpleTLV obj = new SimpleTLV(content, offset, content.length - offset); 

            // перейти на следующий объект
            objects.add(obj); offset += obj.encoded().length; 
        }
        // вернуть раскодированные объекты
        return objects.toArray(new SimpleTLV[objects.size()]); 
    }
    // тип и значение
    private final int tag; private final byte[] value; 

    // конструктор
    public SimpleTLV(int tag, byte[] value) 
    { 
        // проверить корректноть заголовка
        if (tag <= 0 || 0xFF <= tag) throw new IllegalArgumentException(); 

        // проверить корректность размера
        if (value.length > 0xFFFF) throw new IllegalArgumentException();

        // сохранить переданные значения
        this.tag = tag; this.value = value; 
    }
    // раскодировать данные
    public SimpleTLV(byte[] encoded, int offset, int length) throws IOException
    {
        // проверить корректность размера
        if (length < 2) throw new IOException(); 

        // проверить корректность данных
        if (encoded[offset] == 0x00 || encoded[offset] == 0xFF) 
        {
            // при ошибке выбросить исключение
            throw new IOException();
        }
        // в зависимости от размера
        tag = encoded[offset]; if (encoded[offset + 1] != 0xFF)
        {
            // проверить размер данных
            if (length < 2 + encoded[offset + 1]) throw new IOException();

            // создать буфер для данных
            value = new byte[encoded[offset + 1]]; 

            // скопировать данные
            System.arraycopy(encoded, 2 + offset, value, 0, value.length); 
        }
        else { 
            // проверить корректность размера
            if (length < 4) throw new IOException();

            // раскодировать размер данных
            int cb = (encoded[offset + 2] << 8) | encoded[offset + 3]; 

            // проверить размер данных
            if (length < 4 + cb) throw new IOException();

            // скопировать данные
            value = new byte[cb]; System.arraycopy(encoded, 4 + offset, value, 0, cb);
        }
    }
    // значение типа и данных
    public final int tag() { return tag; }

    // содержимое объекта
    public final byte[] value() { return value; }

    // получить закодированное представление
    public final byte[] encoded()
    { 
        // в зависимости от размера данных
        if (value.length < 0xFF)
        {
            // выделить память для представления
            byte[] encoded = new byte[value.length + 2]; 

            // указать заголовок и размер
            encoded[0] = (byte)tag; encoded[1] = (byte)value.length; 

            // скопировать данные
            System.arraycopy(value, 0, encoded, 2, value.length); return encoded; 
        }
        else {
            // выделить память для представления
            byte[] encoded = new byte[value.length + 4]; 

            // указать заголовок
            encoded[0] = (byte)tag; encoded[1] = (byte)0xFF; 

            // закодировать размер
            encoded[2] = (byte)(value.length >>>  8); 
            encoded[3] = (byte)(value.length & 0xFF); 

            // скопировать данные
            System.arraycopy(value, 0, encoded, 4, value.length); return encoded; 
        }
    }
}
