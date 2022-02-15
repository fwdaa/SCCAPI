package aladdin.iso7816;
import aladdin.asn1.*; 
import aladdin.util.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Расширенный заголовок
///////////////////////////////////////////////////////////////////////////
public class ExtendedHeader
{
    // заголовок объекта и внутренние объекты
    public final Header header; public final ExtendedHeader[] children;

    // закодировать объекты
    public static byte[] encode(ExtendedHeader[] headers)
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
    // раскодировать объекты
    public static ExtendedHeader[] decode(
        byte[] content, int offset, int length) throws IOException
    {
        // создать пустой список заголовков
        List<ExtendedHeader> headers = new ArrayList<ExtendedHeader>(); 
        
        // для всех внутренних объектов
        for (int index = 0; index < length; )
        { 
            // раскодировать заголовок
            Header header = Header.decode(content, offset + index, length - index); 

            // для примитивного типа
            if (header.tag.pc.equals(PC.PRIMITIVE))
            {
                // выполнить преобразование типа
                headers.add(new ExtendedHeader(header.tag, header.length)); 

                // перейти на следующий заголовок
                index += header.encoded().length;
            }
            // при отсутствии внутренних объектов
            else if (header.length == 0x00 || header.length == 0x80)
            {
                // выполнить преобразование типа
                headers.add(new ExtendedHeader(header.tag, header.length)); 

                // перейти на следующий заголовок
                index += header.encoded().length;
            }
            else { 
                // раскодировать внутренние элементы
                ExtendedHeader[] children = decode(
                    content, offset + index + header.encoded().length, header.length
                ); 
                // добавить составной расширенный заголовок
                headers.add(new ExtendedHeader(header, children));

                // перейти на следующий заголовок
                index += header.encoded().length + header.length;
            }
        }
        // вернуть раскодированные объекты
        return headers.toArray(new ExtendedHeader[headers.size()]); 
    }
    // конструктор
    public ExtendedHeader(Tag asnTag, int length)
    {
        // проверить тип объекта
        if (asnTag.pc.equals(PC.CONSTRUCTED)) 
        {
            // проверить указанный размер
            if (length != 0x00 && length != 0x80) throw new IllegalArgumentException();
        }
        // указать заголовок объекта
        header = new Header(asnTag, length); 
        
        // указать отсутствие внутренних элементов
        children = new ExtendedHeader[0]; 
    }
    // конструктор
    public ExtendedHeader(Tag asnTag, ExtendedHeader[] children) throws IOException
    {
        // проверить тип объекта
        if (!asnTag.pc.equals(PC.CONSTRUCTED)) throw new IOException(); 
        
        // закодировать внутреннее содержимое
        byte[] content = ExtendedHeader.encode(children); 
        
        // указать заголовок объекта
        header = new Header(asnTag, content.length); this.children = children; 
    }
    // конструктор
    private ExtendedHeader(Header header, ExtendedHeader[] children) throws IOException
    { 
        // проверить тип объекта
        if (!header.tag.pc.equals(PC.CONSTRUCTED)) throw new IOException(); 

        // указать заголовок объекта и дочерние элементы
        this.header = header; this.children = children;
    }
    // закодировать объект
    public final byte[] encoded()
    {
        // закодировать примитивный объект
        if (header.tag.pc.equals(PC.PRIMITIVE)) return header.encoded(); 

        // обработать отсутствие внутренних объектов
        if (header.length == 0x00 || header.length == 0x80) return header.encoded(); 

        // закодировать внутреннее содержимое
        byte[] content = ExtendedHeader.encode(children); 
        
        // закодировать внутренние объекты
        return Encodable.encode(header.tag.asnTag, header.tag.pc, content).encoded(); 
    }
    // извлечь требуемые поля из объекта
    public final IEncodable apply(IEncodable encodable) throws IOException
    {
        // проверить соответствие примитивного элемента
        if (header.tag.pc.equals(PC.PRIMITIVE)) return header.apply(encodable);
        
        // получить тип представления
        Tag tag = new Tag(encodable.tag(), encodable.pc()); 
            
        // проверить совпадение типа и игнорирование объекта
        if (!header.tag.equals(tag) || header.length == 0x00) return null; 

        // проверить указание структуры
        if (header.length == 0x80) return encodable; byte[] content = encodable.content();
            
        // создать список закодированных представлений
        List<byte[]> encodeds = new ArrayList<byte[]>(); 
        
        // для всех внутренних заголовков
        for (int i = 0, position = 0; i < children.length; i++)
        {
            // для всех внутренних объектов
            for (int offset = position; offset < content.length; )
            { 
                // раскодировать закодированное представление
                IEncodable inner = Encodable.decode(content, offset, content.length - offset); 
                
                // перейти на следующий объект
                offset += inner.encoded().length; tag = new Tag(inner.tag(), inner.pc());
                
                // проверить совпадение типа
                if (!children[i].header.tag.equals(tag)) continue; 
                    
                // извлечь требуемые поля из объекта
                IEncodable matched = children[i].apply(inner); position = offset;
                    
                // добавить представление в список
                if (matched != null) encodeds.add(matched.encoded()); break;
            }
        }
        // объединить закодированные представления
        content = Array.concat(encodeds.toArray(new byte[encodeds.size()][])); 
            
        // закодировать объект
        return Encodable.encode(encodable.tag(), encodable.pc(), content); 
    }
    // извлечь закодированное представление из данных
    public IEncodable decodeString(TagScheme tagScheme, byte[] encoded, int[] offset) throws IOException
    {
        // для примитивного элемента
        if (header.tag.pc.equals(PC.PRIMITIVE))
        {
            // проверить размер данных
            if (offset[0] + header.length > encoded.length) throw new IOException(); 

            // выделить память для закодированного представления
            byte[] buffer = new byte[header.length]; 

            // скопировать значение
            System.arraycopy(encoded, offset[0], buffer, 0, header.length); 
            
            // пропустить прочитанные данные
            offset[0] += header.length; 

            // вернуть закодированное представление
            return Encodable.encode(header.tag.asnTag, header.tag.pc, buffer); 
        }
        else { 
            // проверить игнорирование элемента
            if (header.length == 0x80) return null;
        
            // проверить указание внутренних элементов
            if (header.length == 0x80) throw new IllegalStateException(); 

            // создать список закодированных представлений
            List<byte[]> encodeds = new ArrayList<byte[]>(); 

            // для всех внутренних объектов
            for (ExtendedHeader child : children)
            {
                // извлечь закодированное представление
                IEncodable encodable = child.decodeString(tagScheme, encoded, offset); 
                    
                // добавить закодированное представление в список
                if (encodable != null) encodeds.add(encodable.encoded()); 
            }
            // объединить закодированные представления
            byte[] content = Array.concat(encodeds.toArray(new byte[encodeds.size()][])); 
        
            // вернуть закодированное представление
            return Encodable.encode(header.tag.asnTag, header.tag.pc, content); 
        }
    }
}
