package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Tag; 
import aladdin.asn1.*; 
import aladdin.util.*; 
import java.util.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Шаблон для немежотраслевых информационных объектов
///////////////////////////////////////////////////////////////////////////
public class AuthorityTemplate extends DataObjectTemplate
{
    // раскодировать шаблон
    public static AuthorityTemplate decode(
        Tag tag, TagScheme tagScheme, byte[] content) throws IOException
    {
        // создать список объектов идентификации
        List<DataObject> authorityObjects = new ArrayList<DataObject>(); 
        
        // создать список представлений объектов
        List<byte[]> encodeds = new ArrayList<byte[]>();
               
        // для всех внутренних объектов
        for (int offset = 0; offset < content.length; )
        { 
            // раскодировать содержимое
            IEncodable encodable = Encodable.decode(content, offset, content.length - offset); 
            
            // получить тип объекта
            Tag encodableTag = new Tag(encodable.tag(), encodable.pc()); 

            // для объекта идентификации
            if (encodableTag.equals(Tag.OBJECT_IDENTIFIER))
            {
                // раскодировать объект идентификации
                authorityObjects.add(new DataObject(Authority.ISO7816, encodable)); 
            }
            // для объекта идентификации
            else if (encodableTag.equals(Tag.COUNTRY_INDICATOR))
            {
                // раскодировать объект идентификации
                authorityObjects.add(new CountryIndicator(encodable.content())); 
            }
            // для объекта идентификации
            else if (encodableTag.equals(Tag.ISSUER_INDICATOR))
            {
                // раскодировать объект идентификации
                authorityObjects.add(new IssuerIndicator(encodable.content())); 
            }
            // для объекта идентификации
            else if (encodableTag.equals(Tag.APPLICATION_IDENTIFIER))
            {
                // раскодировать объект идентификации
                authorityObjects.add(ApplicationIdentifier.decode(encodable.content())); 
            }
            // сохранить представление объекта
            else encodeds.add(encodable.encoded()); 

            // перейти на следующий объект
            offset += encodable.encoded().length; 
        }
        // при наличии объектов регистрации 
        Authority authority = tagScheme.authority(); if (!authorityObjects.isEmpty()) 
        {
            // указать регистрационный орган
            authority = new Authority(authorityObjects);

            // удалить объекты регистрации
            content = Array.concat(encodeds.toArray(new byte[encodeds.size()][])); 
        }
        // раскодировать шаблон
        return new AuthorityTemplate(authority, tag, tagScheme, content); 
    }
    // конструктор закодирования
    public AuthorityTemplate(Authority authority, Tag tag, DataObject... objects)
    {
        // сохранить переданные параметры
        super(authority, tag, objects); 
    }
    // конструктор раскодирования
    private AuthorityTemplate(Authority authority, 
        Tag tag, TagScheme tagScheme, byte[] content) throws IOException
    {     
        // сохранить переданные параметры
        super(authority, tag, tagScheme, content);  
    } 
    ///////////////////////////////////////////////////////////////////////////
    // Закодировать объект
    ///////////////////////////////////////////////////////////////////////////
    @Override public IEncodable encode(TagScheme tagScheme)
    {
        // получить объекты идентификации
        DataObject[] authorityObjects = authority().objects(); 

        // выделить память для закодированных представлений
        byte[][] encodeds = new byte[authorityObjects.length + 1][];  

        // для всех объектов идентификации
        for (int i = 0; i < authorityObjects.length; i++) 
        {
            // получить закодированные представления
            encodeds[i] = authorityObjects[i].encode(tagScheme).encoded(); 
        }
        // вызвать базовую функцию
        encodeds[authorityObjects.length] = super.encode(tagScheme).content(); 
        
        // закодировать объект
        return Encodable.encode(tag().asnTag, tag().pc, Array.concat(encodeds));
    }
}
