package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Tag;
import aladdin.asn1.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Расширенный список заголовков (0x4D)
///////////////////////////////////////////////////////////////////////////
public class ExtendedHeaderList extends DataObject
{
    // список заголовков
    public final ExtendedHeader[] headers; 

    // конструктор закодирования 
    public ExtendedHeaderList(ExtendedHeader... headers) 
    {     
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.EXTENDED_HEADER_LIST); this.headers = headers; 
    } 
    // конструктор раскодирования
    public ExtendedHeaderList(byte[] content) throws IOException
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.EXTENDED_HEADER_LIST, content); 
            
        // раскодировать заголовки
        headers = ExtendedHeader.decode(content, 0, content.length); 
    }
    // закодированное представление
    @Override public byte[] content() 
    {
        // закодировать заголовки
        return ExtendedHeader.encode(headers); 
    }
    // извлечь требуемые поля из объектов
    public final IEncodable[] apply(IEncodable[] encodables) throws IOException
    {
        // создать список совпавших объектов
        IEncodable[] matches = new IEncodable[headers.length]; 
        
        // для всех заголовков
        for (int i = 0, index = 0; i < headers.length; i++)
        {
            // для всех представлений
            for (int j = index; j < encodables.length; j++)
            {
                // извлечь тип объекта
                Tag tag = new Tag(encodables[j].tag(), encodables[j].pc());
            
                // проверить совпадение типа
                if (!headers[i].header.tag.equals(tag)) continue; index = j + 1;
                    
                // извлечь требуемые поля из объекта
                IEncodable matched = headers[i].apply(encodables[j]); 
                    
                // добавить представление в список
                if (matched != null) matches[i] = matched; break;
            }
        }
        return matches; 
    }
    // извлечь объекты из данных
    public final DataObject[] decodeString(TagScheme tagScheme, 
        Authority outerAuthority, byte[] encoded) throws IOException
    {
        // создать список объектов
        DataObject[] objs = new DataObject[headers.length]; int[] offset = new int[] {0}; 
            
        // для всех заголовков
        for (int i = 0; i < headers.length; i++)
        {
            // извлечь закодированное представление
            IEncodable encodable = headers[i].decodeString(tagScheme, encoded, offset); 
            
            // проверить наличие представления
            if (encodable == null) continue; 
            
            // определить тип содержимого
            Tag tag = new Tag(encodable.tag(), encodable.pc()); 
            
            // раскодировать объект
            objs[i] = tagScheme.decode(outerAuthority, tag, encodable.content()); 
        }
        return objs; 
    }
}
