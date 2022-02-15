package aladdin.iso7816;
import aladdin.iso7816.ber.*; 
import aladdin.asn1.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Регистрирующий орган
///////////////////////////////////////////////////////////////////////////
public class Authority
{ 
    // стандарт ISO 7816
    public static final Authority ISO7816 = new Authority(); 

    // объекты идентификации
    private final List<DataObject> objects;

    // конструктор
    private Authority() { objects = new ArrayList<DataObject>();
        
        // указать идентификатор стандарта
        objects.add(new DataObject(this, new ObjectIdentifier("1.0.7816"))); 
    } 
    // конструктор
    public Authority(Iterable<DataObject> objects) 
    { 
        // создать список объектов
        this.objects = new ArrayList<DataObject>();
        
        // добавить объекты в список
        for (DataObject obj : objects) this.objects.add(obj); 

        // отсортировать список объектов
        Collections.sort(this.objects, new DataObject.Comparator()); 
    } 
    // объекты идентификации
    public final DataObject[] objects() 
    { 
        // объекты идентификации
        return objects.toArray(new DataObject[objects.size()]); 
    }
    // конструктор
    @Override public int hashCode() { int code = 0; 

        // вычислить хэш-код
        for (DataObject obj : objects) code ^= obj.hashCode(); return code;
    }
    // сравнить регистрирующие органы
    @Override public boolean equals(Object other)
    {
        // сравнить регистрирующие органы
        return (other instanceof Authority) && equals((Authority)other); 
    }
    // сравнить регистрирующие органы
    public boolean equals(Authority other) 
    { 
        // проверить совпадение ссылок и наличие объекта 
        if (other == this) return true; if (other == null) return false;
            
        // проверить число объектов
        if (objects.size() != other.objects.size()) return false; 

        // для всех объектов
        for (int i = 0; i < objects.size(); i++)
        {
            // сравнить объекты
            if (!objects.get(i).equals(other.objects.get(i))) return false; 
        }
        return true; 
    }
    // получить элемент коллекции
    public final DataObject get(Tag tag) 
    {
        // найти внутренний объект
        for (DataObject obj : objects) 
        {
            // проверить совпадение идентификаторов
            if (obj.tag().equals(tag)) return obj;
        }
        return null; 
    }
    // идентификатор объекта
    public final ObjectIdentifier objectIdentifier() throws IOException
    {
        // найти объект
        DataObject obj = get(Tag.OBJECT_IDENTIFIER); 

        // проверить наличие элемента
        if (obj == null) return null; 

        // вернуть значение объекта
        return new ObjectIdentifier(
            Encodable.encode(obj.tag().asnTag, obj.tag().pc, obj.content())
        ); 
    }
    // код страны и национальные данные
    public final CountryIndicator countryIndicator() throws IOException
    {
        // найти объект
        DataObject obj = get(Tag.COUNTRY_INDICATOR); 

        // вернуть значение объекта
        return (obj != null) ? new CountryIndicator(obj.content()) : null; 
    }
    // идентификационный номер эмитента
    public final IssuerIndicator issuerIndicator()
    {
        // найти объект
        DataObject obj = get(Tag.ISSUER_INDICATOR); 

        // вернуть значение объекта
        return (obj != null) ? new IssuerIndicator(obj.content()) : null; 
    }
    // идентификатор приложения 
    public final ApplicationIdentifier applicationIdentifier() throws IOException
    {
        // найти объект
        DataObject obj = get(Tag.APPLICATION_IDENTIFIER); 

        // вернуть значение объекта
        return (obj != null) ? ApplicationIdentifier.decode(obj.content()) : null; 
    }
}
