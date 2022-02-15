package aladdin.iso7816.ber;
import aladdin.iso7816.*;
import aladdin.iso7816.Tag;
import aladdin.asn1.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Описание параметров алгоритма
///////////////////////////////////////////////////////////////////////////////
public class CRT extends DataObjectTemplate
{
    // конструктор закодирования
    public CRT(Tag tag, DataObject... objects)
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, tag, objects); 
        
        // проверить наличие идентификатора
        if (get(Tag.context(0x00, PC.PRIMITIVE)).length != 1) throw new IllegalArgumentException(); 
    }
    // конструктор раскодирования
    public CRT(Tag tag, TagScheme tagScheme, byte[] content) throws IOException
    {    
        // проверить корректность данных
        super(Authority.ISO7816, tag, tagScheme, content); 

        // проверить наличие идентификатора
        if (get(Tag.context(0x00, PC.PRIMITIVE)).length != 1) throw new IOException(); 
    } 
    // идентификатор алгоритма
    public final byte[] mechanismReference() 
    { 
        // идентификатор алгоритма
        return get(Tag.context(0x00, PC.PRIMITIVE))[0].content(); 
    }
    // способ использования шаблона
    public final byte usageQualifier() 
    {
        // получить способ использования шаблона
        DataObject[] objs = get(Tag.context(0x15, PC.PRIMITIVE)); 
        
        // проверить наличие способа использования
        if (objs.length == 0 || objs[0].content().length == 0) return 0; 
        
        // вернуть способ использования шаблона
        return objs[0].content()[0]; 
    }
/*    // ссылка на файл
    public final FileReference fileReference() 
    { 
        // найти объект
        BERTLV obj = get(Tag.context(0x01, PC.PRIMITIVE)); 

        // раскодировать объект
        return (obj != null) ? new FileReference(obj.content()) : null; 
    }
    // имя каталога
    public final byte[] nameDF()
    {
        // найти объект
        BERTLV obj = get(Tag.context(0x02, PC.PRIMITIVE)); 

        // раскодировать объект
        return (obj != null) ? obj.content() : null; 
    }
*/    
    ///////////////////////////////////////////////////////////////////////////
    // Описание параметров алгоритма аутентификации
    ///////////////////////////////////////////////////////////////////////////
    public static class AT extends CRT
    {
        // конструктор закодирования
        public AT(Tag tag, DataObject... objects)
        {    
            // сохранить переданные параметры
            super(tag, objects); 
            
            // проверить тип параметров
            if (!tag.equals(Tag.context(0x04, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x05, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
        }
        // конструктор раскодирования
        public AT(Tag tag, TagScheme tagScheme, byte[] content) throws IOException
        {    
            // проверить корректность данных
            super(tag, tagScheme, content); 

            // проверить тип параметров
            if (!tag.equals(Tag.context(0x04, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x05, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IOException(); 
            }
        } 
/*        
        // идентификатор ключа
        public final byte[] secretKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x03, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
        // идентификатор открытого ключа
        public final byte[] publicKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x03, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
        // идентификатор личного ключа
        public final byte[] privateKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x04, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
*/        
    }
    ///////////////////////////////////////////////////////////////////////////
    // Описание параметров алгоритма хэширования
    ///////////////////////////////////////////////////////////////////////////
    public static class HT extends CRT
    {
        // конструктор закодирования
        public HT(Tag tag, DataObject... objects)
        {    
            // сохранить переданные параметры
            super(tag, objects); 
            
            // проверить тип параметров
            if (!tag.equals(Tag.context(0x0A, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x0B, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
        }
        // конструктор раскодирования
        public HT(Tag tag, TagScheme tagScheme, byte[] content) throws IOException
        {    
            // проверить корректность данных
            super(tag, tagScheme, content); 

            // проверить тип параметров
            if (!tag.equals(Tag.context(0x0A, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x0B, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IOException(); 
            }
        } 
/*        
        // идентификатор ключа
        public final byte[] secretKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x03, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
*/        
    }
    ///////////////////////////////////////////////////////////////////////////
    // Описание параметров алгоритма выработки контрольной суммы
    ///////////////////////////////////////////////////////////////////////////
    public static class CCT extends CRT
    {
        // конструктор закодирования
        public CCT(Tag tag, DataObject... objects)
        {    
            // сохранить переданные параметры
            super(tag, objects); 
            
            // проверить тип параметров
            if (!tag.equals(Tag.context(0x14, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x15, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
        }
        // конструктор раскодирования
        public CCT(Tag tag, TagScheme tagScheme, byte[] content) throws IOException
        {    
            // проверить корректность данных
            super(tag, tagScheme, content); 

            // проверить тип параметров
            if (!tag.equals(Tag.context(0x14, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x15, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IOException(); 
            }
        } 
/*        // идентификатор ключа
        public final byte[] secretKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x03, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
*/        
    }
    ///////////////////////////////////////////////////////////////////////////
    // Описание параметров алгоритма шифрования (симметричного или асимметричного)
    ///////////////////////////////////////////////////////////////////////////
    public static class CT extends CRT
    {
        // конструктор закодирования
        public CT(Tag tag, DataObject... objects)
        {    
            // сохранить переданные параметры
            super(tag, objects); 
            
            // проверить тип параметров
            if (!tag.equals(Tag.context(0x18, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x19, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
        }
        // конструктор раскодирования
        public CT(Tag tag, TagScheme tagScheme, byte[] content) throws IOException
        {    
            // проверить корректность данных
            super(tag, tagScheme, content); 

            // проверить тип параметров
            if (!tag.equals(Tag.context(0x18, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x19, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IOException(); 
            }
        } 
/*        
        // идентификатор ключа
        public final byte[] secretKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x03, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
        // идентификатор открытого ключа
        public final byte[] publicKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x03, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
        // идентификатор личного ключа
        public final byte[] privateKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x04, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
*/
    }
    ///////////////////////////////////////////////////////////////////////////
    // Описание параметров алгоритма подписи
    ///////////////////////////////////////////////////////////////////////////
    public static class DST extends CRT
    {
        // конструктор закодирования
        public DST(Tag tag, DataObject... objects)
        {    
            // сохранить переданные параметры
            super(tag, objects); 
            
            // проверить тип параметров
            if (!tag.equals(Tag.context(0x16, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x17, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
        }
        // конструктор раскодирования
        public DST(Tag tag, TagScheme tagScheme, byte[] content) throws IOException
        {    
            // проверить корректность данных
            super(tag, tagScheme, content); 

            // проверить тип параметров
            if (!tag.equals(Tag.context(0x16, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x17, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IOException(); 
            }
        } 
/*        // идентификатор открытого ключа
        public final byte[] publicKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x03, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
        // идентификатор личного ключа
        public final byte[] privateKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x04, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
*/
    }
    ///////////////////////////////////////////////////////////////////////////
    // Описание параметров алгоритма согласования ключа
    ///////////////////////////////////////////////////////////////////////////
    public static class KAT extends CRT
    {
        // конструктор закодирования
        public KAT(Tag tag, DataObject... objects)
        {    
            // сохранить переданные параметры
            super(tag, objects); 
            
            // проверить тип параметров
            if (!tag.equals(Tag.context(0x06, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x07, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException(); 
            }
        }
        // конструктор раскодирования
        public KAT(Tag tag, TagScheme tagScheme, byte[] content) throws IOException
        {    
            // проверить корректность данных
            super(tag, tagScheme, content); 

            // проверить тип параметров
            if (!tag.equals(Tag.context(0x06, PC.CONSTRUCTED)) && 
                !tag.equals(Tag.context(0x07, PC.CONSTRUCTED)))
            {
                // при ошибке выбросить исключение
                throw new IOException(); 
            }
        } 
/*        // идентификатор ключа
        public final byte[] secretKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x03, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
        // идентификатор открытого ключа
        public final byte[] publicKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x03, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
        // идентификатор личного ключа
        public final byte[] privateKeyReference() 
        { 
            // найти объект
            BERTLV obj = get(Tag.context(0x04, PC.PRIMITIVE)); 

            // раскодировать объект
            return (obj != null) ? obj.content() : null; 
        }
*/        
    }
}
