package aladdin.iso7816;
import aladdin.asn1.*; 
import aladdin.util.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////
// Объект данных BER-TLV
///////////////////////////////////////////////////////////////////////
public class DataObject 
{
    // регистрирущий орган, тип и содержимое объекта
    private final Authority authority; private final Tag tag; private byte[] content;

    // конструктор закодирования
    protected DataObject(Authority authority, Tag tag) 
    { 
        // сохранить переданные параметры
        this.authority = authority; this.tag = tag; this.content = null; 
    } 
    // конструктор раскодирования
    public DataObject(CompactTLV obj) { this(Authority.ISO7816, obj.tag(), obj.value()); }

    // конструктор раскодирования
    public DataObject(Authority authority, IEncodable encodable) 
    { 
        // сохранить переданные параметры
        this(authority, new Tag(encodable.tag(), encodable.pc()), encodable.content()); 
    } 
    // конструктор раскодирования
    protected DataObject(Authority authority, Tag tag, byte[] content)
    {
        // сохранить переданные параметры
        this.authority = authority; this.tag = tag; this.content = content;
    }
    // регистрирущий орган
    public final Authority authority() { return authority; }

    // значение типа
    public final Tag tag() { return tag; }

    // содержимое объекта
    public byte[] content() { return content; }  
    // содержимое объекта
    protected final void content(byte[] content) { this.content = content; }  
            
    // хэш-код объекта
    @Override public int hashCode() { return tag.hashCode(); }
    
    // сравнить объекты
    @Override public boolean equals(Object other)
    {
        // сравнить объекты
        return (other instanceof DataObject) && equals((DataObject)other); 
    }
    // сравнить объекты
    public boolean equals(DataObject other) 
    { 
        // проверить совпадение ссылок
        if (other == this) return true; 
 
        // сравнить объекты
        return (other != null) ? compareTo(other) == 0 : false; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Сравнение объектов
    ///////////////////////////////////////////////////////////////////////////
    public static class Comparator implements java.util.Comparator<DataObject>
    {
        // выполнить сравнение объектов
        @Override public int compare(DataObject A, DataObject B) { return A.compareTo(B); }
    }
    // выполнить сравнение объектов
    public int compareTo(DataObject other) 
    { 
        // сравнить типы объектов
        int cmp = tag().compareTo(other.tag()); if (cmp != 0) return cmp; 
        
        // сравнить содержимое объектов
        return Array.compareUnsigned(content(), other.content()); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование объектов
    ///////////////////////////////////////////////////////////////////////////
    public static byte[] encode(TagScheme tagScheme, Iterable<DataObject> objects)
    {
        // выделить память для закодированных представлений
        List<byte[]> encodeds = new ArrayList<byte[]>();  

        // для всех объектов
        for (DataObject obj : objects) 
        {
            // проверить наличие объекта
            if (obj == null) continue; 
                
            // получить закодированное представление
            encodeds.add(obj.encode(tagScheme).encoded());
        }
        // объединить закодированные представления
        return Array.concat(encodeds.toArray(new byte[encodeds.size()][])); 
    }
    public static byte[] encode(TagScheme tagScheme, DataObject[] objects)
    {
        // выделить память для закодированных представлений
        byte[][] encodeds = new byte[objects.length][];  

        // для всех объектов
        for (int i = 0; i < objects.length; i++) 
        {
            // получить закодированное представление
            encodeds[i] = objects[i].encode(tagScheme).encoded();
        }
        // объединить закодированные представления
        return Array.concat(encodeds); 
    }
    public IEncodable encode(TagScheme tagScheme)
    {
        // закодировать объект
        return Encodable.encode(tag().asnTag, tag().pc, content()); 
    }
}
