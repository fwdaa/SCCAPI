package aladdin.iso7816;
import aladdin.asn1.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Составной объект BER-TLV
///////////////////////////////////////////////////////////////////////////
public class DataObjectTemplate extends DataObject implements Iterable<DataObject>
{
    // внутренние объекты
    private final List<DataObject> objects;

    // конструктор закодирования
    public DataObjectTemplate(Authority authority, Tag tag, List<DataObject> objects)
    {
        // проверить корректность данных
        super(authority, tag); if (tag.pc != PC.CONSTRUCTED) throw new IllegalArgumentException(); 
            
        // сохранить переданные параметры
        this.objects = objects;
    }
    // конструктор закодирования
    public DataObjectTemplate(Authority authority, Tag tag, DataObject... objects)
    {
        // сохранить переданные параметры
        this(authority, tag, Arrays.asList(objects));
    }
    // конструктор раскодирования
    public DataObjectTemplate(Authority authority, TagScheme tagScheme, IEncodable encodable) throws IOException
    { 
        // сохранить переданные параметры
        this(authority, new Tag(encodable.tag(), encodable.pc()), tagScheme, encodable.content()); 
    }
    // конструктор раскодирования
    public DataObjectTemplate(Authority authority, Tag tag, TagScheme tagScheme, byte[] content) throws IOException
    {
        // проверить корректность данных
        super(authority, tag); if (tag.pc != PC.CONSTRUCTED) throw new IllegalArgumentException(); 
        
        // создать список закодированных представлений
        List<IEncodable> encodables = new ArrayList<IEncodable>(); 

        // для всех внутренних объектов
        for (int offset = 0; offset < content.length; )
        { 
            // раскодировать содержимое
            IEncodable encodable = Encodable.decode(
                content, offset, content.length - offset
            ); 
            // перейти на следующий объект
            encodables.add(encodable); offset += encodable.encoded().length; 
        }
        // создать список объектов 
        objects = new ArrayList<DataObject>(); 
        
        // раскодировать объекты
        objects.addAll(Arrays.asList(tagScheme.decode(authority, encodables))); 
    }
    // перечислитель объектов
    @Override public final Iterator<DataObject> iterator() { return objects.iterator(); }
    
    // число элементов
    public final int size() { return objects.size(); }

	// получить элемент коллекции
	public final DataObject get(int index) { return objects.get(index); }

    // получить элемент коллекции
    public final DataObject[] get(Tag tag) 
    {
        // создать список объектов
        List<DataObject> objs = new ArrayList<DataObject>(); 
        
        // найти внутренний объект
        for (DataObject obj : objects) 
        {
            // проверить совпадение идентификаторов
            if (obj.tag().equals(tag)) objs.add(obj);
        }
        // вернуть список объектов
        return objs.toArray(new DataObject[objs.size()]); 
    }
    // сравнить объекты
    @Override public int compareTo(DataObject other)
    {
        // проверить совпадение ссылок
        if (other == this) return 0; 

        // сравнить типы объектов
        int cmp = tag().compareTo(other.tag()); if (cmp != 0) return cmp; 

        // сравнить объекты
        return compareTo((DataObjectTemplate)other); 
    }
    // сравнить объекты
    public int compareTo(DataObjectTemplate other) 
    { 
        // проверить совпадение ссылок
        if (other == this) return 0; 

        // сравнить типы объектов
        int cmp = tag().compareTo(other.tag()); 

        // для всех объектов
        for (int i = 0; cmp == 0 && i < objects.size(); i++)
        {
            // проверить наличие объекта
            if (other.objects.size() <= i) return 1; 

            // сравнить значения объектов
            cmp = objects.get(i).compareTo(other.objects.get(i)); 
        }
        // проверить совпадение объектов
        if (cmp != 0) return cmp; 

        // проверить совпадение размеров
        return (objects.size() == other.objects.size()) ? 0 : -1; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Закодировать объект
    ///////////////////////////////////////////////////////////////////////////
    @Override public IEncodable encode(TagScheme tagScheme)
    {
        // закодировать внутренние объекты
        byte[] content = DataObject.encode(tagScheme, objects); 
        
        // закодировать составной объект
        return Encodable.encode(tag().asnTag, tag().pc, content); 
    }
}
