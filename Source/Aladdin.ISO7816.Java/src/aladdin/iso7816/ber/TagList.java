package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Tag;
import aladdin.asn1.*; 
import aladdin.util.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Список тэгов (0x5С)
///////////////////////////////////////////////////////////////////////////
public class TagList extends DataObject
{
    // список тэгов
    public final Tag[] tags; 

    // конструктор закодирования 
    public TagList(Tag... tags) 
    { 
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.TAG_LIST); this.tags = tags; 
    } 
    // конструктор раскодирования
    public TagList(byte[] content) throws IOException
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.TAG_LIST, content); 
        
        // создать пустой список тэгов
        List<Tag> tagList = new ArrayList<Tag>(); 
        
        // для всех внутренних объектов
        for (int offset = 0; offset < content.length; )
        { 
            // раскодировать тэг
            Tag tag = Tag.decode(content, offset, content.length - offset); 

            // перейти на следующий объект
            tagList.add(tag); offset += tag.encoded.length;
        }
        // сохранить раскодированные объекты
        this.tags = tagList.toArray(new Tag[tagList.size()]); 
    }
    // закодированное представление
    @Override public byte[] content()
    {
        // выделить память для закодированных представлений
        byte[][] encodeds = new byte[tags.length][];  

        // для всех тэгов
        for (int i = 0; i < tags.length; i++) 
        {
            // получить закодированное представление
            encodeds[i] = tags[i].encoded;
        }
        // объединить закодированные представления
        return Array.concat(encodeds); 
    }
    // извлечь требуемые поля из объектов
    public final IEncodable[] apply(IEncodable[] encodables) throws IOException
    {
        // проверить наличие тэгов
        if (tags.length == 0) return encodables; 
        
        // создать список совпавших объектов
        IEncodable[] matches = new IEncodable[tags.length]; 
        
        // для всех заголовков
        for (int i = 0, index = 0; i < tags.length; i++)
        {
            // для всех представлений
            for (int j = index; j < encodables.length; j++)
            {
                // извлечь тип объекта
                Tag tag = new Tag(encodables[j].tag(), encodables[j].pc());
            
                // проверить совпадение типа
                if (!tags[i].equals(tag)) continue; index = j + 1; 
                    
                // добавить представление в список
                matches[i] = encodables[j]; break; 
            }
        }
        return matches; 
    }
}
