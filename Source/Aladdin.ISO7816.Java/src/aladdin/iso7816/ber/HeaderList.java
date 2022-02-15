package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Tag;
import aladdin.asn1.*;
import aladdin.util.*; 
import java.util.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Список заголовков (0x5D)
///////////////////////////////////////////////////////////////////////////
public class HeaderList extends DataObject
{
    // список заголовков
    public final Header[] headers; 

    // конструктор закодирования 
    public HeaderList(Header... headers) 
    { 
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.HEADER_LIST); this.headers = headers; 
    } 
    // конструктор раскодирования
    public HeaderList(byte[] content) throws IOException
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.HEADER_LIST, content); 
        
        // создать пустой список заголовков
        List<Header> headerList = new ArrayList<Header>(); 
        
        // для всех внутренних объектов
        for (int offset = 0; offset < content.length; )
        { 
            // раскодировать заголовок
            Header header = Header.decode(content, offset, content.length - offset); 

            // перейти на следующий объект
            headerList.add(header); offset += header.encoded().length;
        }
        // сохранить раскодированные объекты
        this.headers = headerList.toArray(new Header[headerList.size()]); 
    }
    // закодированное представление
    @Override public byte[] content()
    {
        // выделить память для закодированных представлений
        byte[][] encodeds = new byte[headers.length][];  

        // для всех заголовков
        for (int i = 0; i < headers.length; i++) 
        {
            // получить закодированное представление
            encodeds[i] = headers[i].encoded();
        }
        // объединить закодированные представления
        return Array.concat(encodeds); 
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
                if (!headers[i].tag.equals(tag)) continue; index = j + 1; 
                    
                // извлечь требуемые поля из объекта
                IEncodable matched = headers[i].apply(encodables[j]); 
                    
                // добавить представление в список
                if (matched != null) matches[i] = matched; break;
            }
        }
        return matches; 
    }
    // извлечь объекты из данных
    public DataObject[] decodeString(TagScheme tagScheme, 
        Authority outerAuthority, byte[] encoded) throws IOException
    {
        // создать список объектов
        DataObject[] objs = new DataObject[headers.length]; int offset = 0; 

        // для всех объектов
        for (int i = 0; i < headers.length; offset += headers[i].length, i++)
        {
            // проверить наличие объекта
            if (offset + headers[i].length > encoded.length) throw new IOException(); 

            // выделить память для закодированного представления
            byte[] content = new byte[headers[i].length]; 

            // скопировать значение
            System.arraycopy(encoded, offset, content, 0, headers[i].length); 

            // раскодировать объект
            objs[i] = tagScheme.decode(outerAuthority, headers[i].tag, content); 
        }
        return objs; 
    }
}
