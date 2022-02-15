package aladdin.iso7816.ber;
import aladdin.iso7816.*; 
import aladdin.iso7816.Tag; 
import aladdin.asn1.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Шаблон безопасной среды (0x7B)
///////////////////////////////////////////////////////////////////////////
public class SE extends DataObjectTemplate
{
    // конструктор закодирования
    public SE(DataObject... objects) 
    {     
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.SECURITY_ENVIRONMENT_TEMPLATE, objects); 
            
        // получить идентификатор криптографической среды
        DataObject[] objs = get(Tag.context(0x00, PC.PRIMITIVE)); 
            
        // проверить наличие идентификатора
        if (objs.length != 1 || objs[0].content().length != 1)
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException();
        }
    }
    // конструктор раскодирования
    public SE(TagScheme tagScheme, byte[] content) throws IOException
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.SECURITY_ENVIRONMENT_TEMPLATE, tagScheme, content); 
            
        // получить идентификатор криптографической среды
        DataObject[] objs = get(Tag.context(0x00, PC.PRIMITIVE)); 
            
        // проверить наличие идентификатора
        if (objs.length != 1 || objs[0].content().length != 1)
        {
            // при ошибке выбросить исключение
            throw new IOException();
        }
    }
    // идентификатор криптографической среды
    public final int id() 
    {
        // получить требуемый объект
        DataObject obj = get(Tag.context(0x14, PC.PRIMITIVE))[0]; 
            
        // раскодировать идентификатор
        return obj.content()[0] & 0xFF; 
    }
    // информация о состоянии
    public final LifeCycle lifeCycle()
    {
        // указать тип объекта
        Tag tag = Tag.context(0x0A, PC.PRIMITIVE); 
            
        // получить требуемые объекты
        DataObject[] objs = get(tag); if (objs.length == 0) return null; 
            
        // раскодировать объект
        return new LifeCycle(tag, objs[0].content()); 
    }
    // описание идентификаторов алгоритмов
    public final MechanismID[] mechanismIDs(TagScheme tagScheme) throws IOException 
    {
        // получить требуемые объекты
        DataObject[] objs = get(Tag.context(0x0C, PC.CONSTRUCTED)); 

        // выделить список требуемого размера
        MechanismID[] mechanismsIDs = new MechanismID[objs.length]; 
            
        // для всех объектов
        for (int i = 0; i < objs.length; i++)
        {
            // раскодировать объект
            mechanismsIDs[i] = new MechanismID(tagScheme, objs[i].content());
        }
        // вернуть список объектов
        return mechanismsIDs; 
    }
    // получить параметры алгоритма
    public final CRT.AT authenticationParameters(TagScheme tagScheme) throws IOException 
    {
        // указать тип объекта
        Tag tag = Tag.context(0x04, PC.CONSTRUCTED); 
            
        // получить требуемые объекты
        DataObject[] objs = get(tag); if (objs.length == 0) return null; 
            
        // раскодировать объект
        return new CRT.AT(tag, tagScheme, objs[0].content()); 
    }
    // получить параметры алгоритма
    public final CRT.HT hashParameters(TagScheme tagScheme) throws IOException 
    {
        // указать тип объекта
        Tag tag = Tag.context(0x0A, PC.CONSTRUCTED); 
            
        // получить требуемые объекты
        DataObject[] objs = get(tag); if (objs.length == 0) return null; 
            
        // раскодировать объект
        return new CRT.HT(tag, tagScheme, objs[0].content()); 
    }
    // получить параметры алгоритма
    public final CRT.CCT macParameters(TagScheme tagScheme) throws IOException 
    {
        // указать тип объекта
        Tag tag = Tag.context(0x14, PC.CONSTRUCTED); 
            
        // получить требуемые объекты
        DataObject[] objs = get(tag); if (objs.length == 0) return null; 
            
        // раскодировать объект
        return new CRT.CCT(tag, tagScheme, objs[0].content()); 
    }
    // получить параметры алгоритма
    public final CRT.CT cipherParameters(TagScheme tagScheme) throws IOException 
    {
        // указать тип объекта
        Tag tag = Tag.context(0x18, PC.CONSTRUCTED); 
            
        // получить требуемые объекты
        DataObject[] objs = get(tag); if (objs.length == 0) return null; 
            
        // раскодировать объект
        return new CRT.CT(tag, tagScheme, objs[0].content()); 
    }
    // получить параметры алгоритма
    public final CRT.DST signParameters(TagScheme tagScheme) throws IOException 
    {
        // указать тип объекта
        Tag tag = Tag.context(0x16, PC.CONSTRUCTED); 
            
        // получить требуемые объекты
        DataObject[] objs = get(tag); if (objs.length == 0) return null; 
          
        // раскодировать объект
        return new CRT.DST(tag, tagScheme, objs[0].content()); 
    }
    // получить параметры алгоритма
    public final CRT.KAT keyAgreementParameters(TagScheme tagScheme) throws IOException 
    {
        // указать тип объекта
        Tag tag = Tag.context(0x06, PC.CONSTRUCTED); 
           
        // получить требуемые объекты
        DataObject[] objs = get(tag); if (objs.length == 0) return null; 
            
        // раскодировать объект
        return new CRT.KAT(tag, tagScheme, objs[0].content()); 
    }
}
