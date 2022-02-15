package aladdin.iso7816;
import aladdin.iso7816.ber.*;
import aladdin.asn1.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Источник распределения тэгов 
///////////////////////////////////////////////////////////////////////////
public abstract class TagScheme extends DataObjectTemplate
{
    // схема распределения тегов по умолчанию
    public static final TagScheme DEFAULT = new Standard(); 
    
    // раскодировать источник распределения тэгов 
    public static TagScheme decodeTagScheme(Tag tag, byte[] content) throws IOException
    {
        // создать список объектов
        List<DataObject> objects = new ArrayList<DataObject>(); 
            
        // раскодировать закодированное представление
        IEncodable encodable = Encodable.decode(content, 0, content.length); 
            
        // раскодировать объект
        DataObject obj = TagScheme.DEFAULT.decode(Authority.ISO7816, encodable); 
            
        // добавить объект в список и перейти на следующий объект
        objects.add(obj); int offset = encodable.encoded().length; 
        
        // для всех внутренних объектов
        for (; offset < content.length; offset += encodable.encoded().length)
        { 
            // раскодировать закодированное представление
            encodable = Encodable.decode(content, offset, content.length - offset); 

            // раскодировать объект и добавить его в список
            objects.add(TagScheme.DEFAULT.decode(Authority.ISO7816, encodable)); 
        }
        if (tag.equals(Tag.COEXISTENT_TAG_SCHEME))
        {
            // вернуть способ кодирования
            return new TagScheme.Coexistent(new Authority(objects)); 
        }
        else {
            // указать тип объекта
            Tag encodableTag = new Tag(encodable.tag(), encodable.pc()); 

            // проверить тип представления
            if (!encodableTag.equals(Tag.context(0x00, PC.PRIMITIVE)))
            {
                // вернуть способ кодирования
                return new TagScheme.Compatible(new Authority(objects)); 
            }
            // создать список объектов органа регистрации
            List<DataObject> authorityObjects = new ArrayList<DataObject>(); 
            
            // заполнить список объектов органа регистрации
            for (int i = 1; i < objects.size(); i++) authorityObjects.add(objects.get(i)); 

            // вернуть способ кодирования
            return new TagScheme.Standard(new Authority(authorityObjects), objects); 
        }
    }
    // конструктор закодирования
    protected TagScheme(Tag tag, List<DataObject> objects) 
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, tag, objects);  
    }
    // конструктор закодирования
    protected TagScheme(Tag tag, DataObject... objects) 
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, tag, objects);  
    }
    // конструктор раскодирования
    protected TagScheme(Tag tag, byte[] content) throws IOException
    { 
        // сохранить переданные параметры
        super(Authority.ISO7816, tag, TagScheme.DEFAULT, content); 
    }
    // закодировать объекты
    public abstract IEncodable[] encode(DataObject[] objects); 
    // раскодировать объекты
    public abstract DataObject[] decode(
        Authority outerAuthority, Iterable<IEncodable> encodables) throws IOException; 
    
    // раскодировать объект
    public final DataObject decode(Authority outerAuthority, IEncodable encodable) throws IOException
    {
        // указать тип объекта
        Tag tag = new Tag(encodable.tag(), encodable.pc()); 

        // раскодировать объект
        return decode(outerAuthority, tag, encodable.content()); 
    }
    // раскодировать объект
    public abstract DataObject decode(
        Authority outerAuthority, Tag tag, byte[] content) throws IOException; 
        
    // раскодировать межотраслевой объект
    protected final DataObject decodeISO7816(Tag tag, byte[] content) throws IOException
    {
        // для сосуществующей схемы кодирования
        if (tag.equals(Tag.COEXISTENT_TAG_SCHEME))
        {
            // раскодировать сосуществующую схему кодирования
            return new TagScheme.Coexistent(content); 
        }
        // для шаблона межотраслевых объектов
        if (tag.equals(Tag.INTERINDUSTRY_TEMPLATE))
        {
            // раскодировать шаблон межлотраслевых объектов
            return new InterindustryTemplate(this, content); 
        }
        // для специальных составных объектов
        if (tag.equals(Tag.FILE_CONTROL_PARAMETERS))
        {
            // раскодировать специальный составной объект
            return new FileControlParameters(this, content); 
        }
        // для специальных составных объектов
        if (tag.equals(Tag.FILE_MANAGEMENT_DATA))
        {
            // раскодировать специальный составной объект
            return new FileManagementData(this, content); 
        }
        // для специальных составных объектов
        if (tag.equals(Tag.FILE_CONTROL_INFORMATION))
        {
            // раскодировать специальный составной объект
            return new FileControlInformation(this, content); 
        }
        // для специальных составных объектов
        if (tag.equals(Tag.SECURE_MESSAGING))
        {
            // раскодировать специальный составной объект
            return new SecureMessaging(this, content); 
        }
        // для составных объектов
        if (tag.pc.equals(PC.CONSTRUCTED))
        {
            // раскодировать составной объект
            return new DataObjectTemplate(Authority.ISO7816, tag, this, content); 
        }
        else {
            // раскодировать примитивный объект
            return new DataObject(Authority.ISO7816, tag, content); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Источник распределения стандартных тэгов 
    ///////////////////////////////////////////////////////////////////////
    public static class Standard extends TagScheme
    {
        // орган регистрации внутренних тегов
        private final Authority subAuthority; 
        
        // конструктор закодирования
        private Standard() { this(null, new ArrayList<DataObject>()); }
            
        // конструктор закодирования
        private Standard(Authority subAuthority, List<DataObject> objects) 
        {
            // сохранить переданные параметры
            super(Tag.COMPATIBLE_TAG_SCHEME, objects);  

            // сохранить переданные параметры
            this.subAuthority = subAuthority;
        }
        // закодировать объекты
        @Override public IEncodable[] encode(DataObject[] objects)
        {
            // создать список закодированных представлений
            List<IEncodable> encodables = new ArrayList<IEncodable>(); 
            
            // новая схема кодирования объектов
            TagScheme redirectTagScheme = null; 
            
            // для всех объектов
            for (DataObject obj : objects)
            {
                // для межотраслевых информационных объектов
                if (obj.authority().equals(Authority.ISO7816))
                {
                    // закодировать объект
                    encodables.add(obj.encode(this)); continue; 
                }
                // при совпадении органа регистрации
                if (subAuthority != null && obj.authority().equals(subAuthority))
                {
                    // сохранить схему кодирования
                    if (redirectTagScheme == null) redirectTagScheme = this; 
                    
                     // проверить совпадение схемы кодирования
                    else if (redirectTagScheme != this)
                    {
                        // при ошибке выбросить исключение
                        throw new UnsupportedOperationException(); 
                    }
                }
                // при отсутствии переопределения схемы кодирования
                else if (redirectTagScheme == null)
                {
                    // создать описание новой схемы кодирования
                    redirectTagScheme = new TagScheme.Coexistent(obj.authority()); 

                    // вставить новую схему кодирования
                    encodables.add(redirectTagScheme.encode(this)); 
                }
                else {
                    // проверить тип органа регистрации
                    if (!(redirectTagScheme instanceof TagScheme.Coexistent))
                    {
                        // при ошибке выбросить исключение
                        throw new UnsupportedOperationException(); 
                    }
                    // выполнить преобразование типа
                    TagScheme.Coexistent tagScheme = (TagScheme.Coexistent)redirectTagScheme; 
                        
                    // проверить совпадение органа регистрации
                    if (!obj.authority().equals(tagScheme.schemeAuthority()))
                    {
                        // при ошибке выбросить исключение
                        throw new UnsupportedOperationException(); 
                    }
                }
                // закодировать объект
                encodables.add(obj.encode(redirectTagScheme)); 
            }
            // вернуть список закодированных представлений
            return encodables.toArray(new IEncodable[encodables.size()]); 
        }
        // раскодировать объекты
        @Override public DataObject[] decode(
            Authority outerAuthority, Iterable<IEncodable> encodables) throws IOException
        {
            // скорректировать параметры
            if (outerAuthority == null) outerAuthority = (subAuthority != null) ? subAuthority : Authority.ISO7816; 
            
            // создать список объектов
            List<DataObject> objects = new ArrayList<DataObject>(); TagScheme tagScheme = this;
            
            // для всех объектов
            for (IEncodable encodable : encodables)
            { 
                // указать тип объекта
                Tag tag = new Tag(encodable.tag(), encodable.pc()); 
            
                // при указании схемы объектов
                if (tag.equals(Tag.COEXISTENT_TAG_SCHEME) || tag.equals(Tag.COMPATIBLE_TAG_SCHEME))
                {
                    // проверить отсутствие переопределения схемы кодирования
                    if (tagScheme != this) throw new UnsupportedOperationException(); 
                    
                    // раскодировать новый орган регистрации
                    tagScheme = TagScheme.decodeTagScheme(tag, encodable.content()); 
                }
            }
            // для всех объектов
            for (IEncodable encodable : encodables)
            { 
                // указать тип объекта
                Tag tag = new Tag(encodable.tag(), encodable.pc()); 
            
                // проверить отсутствие схемы объектов
                if (tag.equals(Tag.COEXISTENT_TAG_SCHEME)) continue; 
                if (tag.equals(Tag.COMPATIBLE_TAG_SCHEME)) continue; 
            
                // для шаблона межотраслевых объектов
                if (tag.equals(Tag.INTERINDUSTRY_TEMPLATE))
                {
                    // раскодировать шаблон
                    DataObjectTemplate template = new InterindustryTemplate(this, encodable.content()); 
                    
                    // добавить объекты в список
                    for (DataObject obj : template) objects.add(obj); 
                }
                // раскодировать объект
                else objects.add(tagScheme.decode(outerAuthority, encodable)); 
            }
            // вернуть список объектов
            return objects.toArray(new DataObject[objects.size()]); 
        }
        // раскодировать объекты
        @Override public DataObject decode(Authority outerAuthority, Tag tag, byte[] content) throws IOException
        {
            // скорректировать параметры
            if (outerAuthority == null) outerAuthority = (subAuthority != null) ? subAuthority : Authority.ISO7816; 
            
            // 1) outerAuthority == Authority.ISO7816 (по умолчанию)
            // 2) outerAuthority == subAuthority      (для длинных тэгов)
            
            // для стандартных объектов ISO 8825
            if (tag.tagClass().equals(TagClass.UNIVERSAL))
            {
                // раскодировать межотраслевой объект
                return super.decodeISO7816(tag, content); 
            }
            // для объектов приложения
            else if (tag.tagClass().equals(TagClass.APPLICATION))
            {
                // для межотраслевых объектов
                if (tag.tagValue() < 128 || 512 <= tag.tagValue())
                {
                    // раскодировать межотраслевой объект
                    return super.decodeISO7816(tag, content); 
                }
                else { 
                    // проверить наличие органа регистрации
                    if (subAuthority == null) throw new UnsupportedOperationException(); 
                
                    // для составных объектов
                    if (tag.pc.equals(PC.CONSTRUCTED))
                    {
                        // раскодировать составной объект
                        return new DataObjectTemplate(subAuthority, tag, this, content); 
                    }
                    else {
                        // раскодировать примитивный объект
                        return new DataObject(subAuthority, tag, content); 
                    }
                }
            }
            // для контекстных объектов
            else if (tag.tagClass().equals(TagClass.CONTEXT))
            {
                // для составных объектов
                if (tag.pc.equals(PC.CONSTRUCTED))
                {
                    // раскодировать составной объект
                    return new DataObjectTemplate(outerAuthority, tag, this, content); 
                }
                else {
                    // раскодировать примитивный объект
                    return new DataObject(outerAuthority, tag, content); 
                }
            }
            // при ошибке выбросить исключение
            else throw new UnsupportedOperationException(); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Источник распределения совместимых тэгов 
    ///////////////////////////////////////////////////////////////////////
    public static class Compatible extends TagScheme
    {
        // орган регистрации тегов
        private final Authority schemeAuthority; 
        
        // конструктор закодирования
        private Compatible(Authority schemeAuthority) 
        {
            // сохранить переданные параметры
            super(Tag.COMPATIBLE_TAG_SCHEME, schemeAuthority.objects());  

            // сохранить переданные параметры
            this.schemeAuthority = schemeAuthority;
        }
        // орган регистрации тегов
        public final Authority schemeAuthority() { return schemeAuthority; } 
        
        // закодировать объекты
        @Override public IEncodable[] encode(DataObject[] objects)
        {
            // создать список закодированных представлений
            List<IEncodable> encodables = new ArrayList<IEncodable>(); 
            
            // новый схема кодирования объектов
            TagScheme redirectTagScheme = null; 
            
            // для всех объектов
            for (DataObject obj : objects)
            {
                // для шаблона немежотраслевых информационных объектов
                if (obj.tag().equals(Tag.AUTHORITY_TEMPLATE0) || 
                    obj.tag().equals(Tag.AUTHORITY_TEMPLATE1) || 
                    obj.tag().equals(Tag.AUTHORITY_TEMPLATE2) || 
                    obj.tag().equals(Tag.AUTHORITY_TEMPLATE4) || 
                    obj.tag().equals(Tag.AUTHORITY_TEMPLATE5) || 
                    obj.tag().equals(Tag.AUTHORITY_TEMPLATE6) || 
                    obj.tag().equals(Tag.AUTHORITY_TEMPLATE7))
                {
                    // указать используемую схему кодирования
                    if (redirectTagScheme == null) redirectTagScheme = this; 
                        
                     // проверить совпадение схемы кодирования
                    else if (redirectTagScheme != this)
                    {
                        // при ошибке выбросить исключение
                        throw new UnsupportedOperationException(); 
                    }
                    // закодировать объект
                    encodables.add(obj.encode(this)); continue; 
                }
                // для межотраслевых информационных объектов
                if (obj.authority().equals(Authority.ISO7816))
                {
                    // закодировать объект
                    encodables.add(obj.encode(this)); continue; 
                }
                // при совпадении органа регистрации
                if (obj.authority().equals(schemeAuthority))
                {
                    // указать используемую схему кодирования
                    if (redirectTagScheme == null) redirectTagScheme = this; 
                        
                     // проверить совпадение схемы кодирования
                    else if (redirectTagScheme != this)
                    {
                        // при ошибке выбросить исключение
                        throw new UnsupportedOperationException(); 
                    }
                }
                // при отсутствии переопределения схемы кодирования
                else if (redirectTagScheme == null)
                {
                    // создать описание новой схемы кодирования
                    redirectTagScheme = new TagScheme.Coexistent(obj.authority()); 

                    // вставить новую схему кодирования
                    encodables.add(redirectTagScheme.encode(this)); 
                }
                else {
                    // проверить тип органа регистрации
                    if (!(redirectTagScheme instanceof TagScheme.Coexistent))
                    {
                        // при ошибке выбросить исключение
                        throw new UnsupportedOperationException(); 
                    }
                    // выполнить преобразование типа
                    TagScheme.Coexistent tagScheme = (TagScheme.Coexistent)redirectTagScheme; 
                        
                    // проверить совпадение органа регистрации
                    if (!obj.authority().equals(tagScheme.schemeAuthority()))
                    {
                        // при ошибке выбросить исключение
                        throw new UnsupportedOperationException(); 
                    }
                }
                // закодировать объект
                encodables.add(obj.encode(redirectTagScheme)); 
            }
            // вернуть список закодированных представлений
            return encodables.toArray(new IEncodable[encodables.size()]); 
        }
        // раскодировать объекты
        @Override public DataObject[] decode(
            Authority outerAuthority, Iterable<IEncodable> encodables) throws IOException
        {
            // скорректировать параметры
            if (outerAuthority == null) outerAuthority = schemeAuthority; 
            
            // создать список объектов
            List<DataObject> objects = new ArrayList<DataObject>(); TagScheme tagScheme = this;
            
            // для всех объектов
            for (IEncodable encodable : encodables)
            { 
                // указать тип объекта
                Tag tag = new Tag(encodable.tag(), encodable.pc()); 
            
                // при указании схемы объектов
                if (tag.equals(Tag.COEXISTENT_TAG_SCHEME) || tag.equals(Tag.COMPATIBLE_TAG_SCHEME))
                {
                    // проверить отсутствие переопределения схемы кодирования
                    if (tagScheme != this) throw new UnsupportedOperationException(); 
                    
                    // раскодировать новый орган регистрации
                    tagScheme = TagScheme.decodeTagScheme(tag, encodable.content()); 
                }
            }
            // для всех объектов
            for (IEncodable encodable : encodables)
            { 
                // указать тип объекта
                Tag tag = new Tag(encodable.tag(), encodable.pc()); 
            
                // проверить отсутствие схемы объектов
                if (tag.equals(Tag.COEXISTENT_TAG_SCHEME)) continue; 
                if (tag.equals(Tag.COMPATIBLE_TAG_SCHEME)) continue; 
            
                // для шаблона межотраслевых объектов
                if (tag.equals(Tag.INTERINDUSTRY_TEMPLATE))
                {
                    // раскодировать шаблон
                    DataObjectTemplate template = new InterindustryTemplate(this, encodable.content()); 
                    
                    // добавить объекты в список
                    for (DataObject obj : template) objects.add(obj); 
                }
                // раскодировать объект
                else objects.add(tagScheme.decode(outerAuthority, encodable)); 
            }
            // вернуть список объектов
            return objects.toArray(new DataObject[objects.size()]); 
        }
        // раскодировать объекты
        @Override public DataObject decode(Authority outerAuthority, Tag tag, byte[] content) throws IOException
        {
            // скорректировать параметры
            if (outerAuthority == null) outerAuthority = schemeAuthority; 
            
            // 1) outerAuthority == Authority.ISO7816            (по умолчанию)
            // 2) outerAuthority == schemeAuthority              (в AuthorityTemplate без переопределения)
            // 3) outerAuthority == AuthorityTemplate.Authority  (в AuthorityTemplate c переопределением)
            
            // для стандартных объектов ISO 8825
            if (tag.tagClass().equals(TagClass.UNIVERSAL))
            {
                // раскодировать межотраслевой объект
                return super.decodeISO7816(tag, content); 
            }
            // для объектов приложения
            else if (tag.tagClass().equals(TagClass.APPLICATION))
            {
                // для шаблона немежотраслевых информационных объектов
                if (tag.equals(Tag.AUTHORITY_TEMPLATE0) || 
                    tag.equals(Tag.AUTHORITY_TEMPLATE1) || 
                    tag.equals(Tag.AUTHORITY_TEMPLATE2) || 
                    tag.equals(Tag.AUTHORITY_TEMPLATE4) || 
                    tag.equals(Tag.AUTHORITY_TEMPLATE5) || 
                    tag.equals(Tag.AUTHORITY_TEMPLATE6) || 
                    tag.equals(Tag.AUTHORITY_TEMPLATE7))
                {
                    // раскодировать шаблон немежотраслевых информационных объектов
                    return AuthorityTemplate.decode(tag, this, content); 
                }
                // раскодировать межотраслевой объект
                else return super.decodeISO7816(tag, content); 
            }
            // для контекстных объектов
            else if (tag.tagClass().equals(TagClass.CONTEXT))
            {
                // для составных объектов
                if (tag.pc.equals(PC.CONSTRUCTED))
                {
                    // раскодировать составной объект
                    return new DataObjectTemplate(outerAuthority, tag, this, content); 
                }
                else {
                    // раскодировать примитивный объект
                    return new DataObject(outerAuthority, tag, content); 
                }
            }
            // при ошибке выбросить исключение
            else throw new UnsupportedOperationException(); 
        }
    }
    ///////////////////////////////////////////////////////////////////////
    // Источник распределения сосуществующих тэгов 
    ///////////////////////////////////////////////////////////////////////
    public static class Coexistent extends TagScheme
    {
        // орган регистрации тегов
        private final Authority schemeAuthority; 
        
        // конструктор закодирования
        public Coexistent(Authority schemeAuthority) 
        {
            // сохранить переданные параметры
            super(Tag.COEXISTENT_TAG_SCHEME, schemeAuthority.objects());  

            // сохранить переданные параметры
            this.schemeAuthority = schemeAuthority;
        }
        // конструктор раскодирования
        public Coexistent(byte[] content) throws IOException
        { 
            // сохранить переданные параметры
            super(Tag.COEXISTENT_TAG_SCHEME, content); 
            
            // раскодировать орган регистрации тегов
            schemeAuthority = new Authority(this); 
        }
        // орган регистрации тегов
        public final Authority schemeAuthority() { return schemeAuthority; } 
        
        // закодировать объекты
        @Override public IEncodable[] encode(DataObject[] objects)
        {
            // создать список закодированных представлений
            List<IEncodable> encodables = new ArrayList<IEncodable>(); 
            
            // новый схема кодирования объектов
            TagScheme redirectTagScheme = null; 
            
            // для всех объектов
            for (int i = 0; i < objects.length; i++)
            {
                // для специальных объектов
                if (objects[i].tag().equals(Tag.COEXISTENT_TAG_SCHEME   ) || 
                    objects[i].tag().equals(Tag.INTERINDUSTRY_TEMPLATE  ) || 
                    objects[i].tag().equals(Tag.FILE_CONTROL_PARAMETERS ) || 
                    objects[i].tag().equals(Tag.FILE_MANAGEMENT_DATA    ) || 
                    objects[i].tag().equals(Tag.FILE_CONTROL_INFORMATION) || 
                    objects[i].tag().equals(Tag.SECURE_MESSAGING        ))
                {
                    // закодировать объект
                    encodables.add(objects[i].encode(this)); continue; 
                }
                // создать список межотраслевых объектов
                List<DataObject> objsISO7816 = new ArrayList<DataObject>(); 
                
                // для межотраслевых объектов
                for (; i < objects.length; i++)
                {
                    // проверить регистрирующий орган
                    if (!objects[i].authority().equals(Authority.ISO7816)) break;
                    
                    // добавить объект в список
                    objsISO7816.add(objects[i]); 
                }
                // при наличии межотраслевых объектов
                if (!objsISO7816.isEmpty()) { 
                    
                    // создать шаблон межотраслевых объектов
                    InterindustryTemplate template = new InterindustryTemplate(objsISO7816); 
                    
                    // закодировать шаблон
                    encodables.add(template.encode(this)); continue; 
                }
                // при совпадении органа регистрации
                if (objects[i].authority().equals(schemeAuthority))
                {
                    // указать используемую схему кодирования
                    if (redirectTagScheme == null) redirectTagScheme = this; 
                        
                     // проверить совпадение схемы кодирования
                    else if (redirectTagScheme != this)
                    {
                        // при ошибке выбросить исключение
                        throw new UnsupportedOperationException(); 
                    }
                }
                // при отсутствии переопределения схемы кодирования
                else if (redirectTagScheme == null)
                {
                    // создать описание новой схемы кодирования
                    redirectTagScheme = new TagScheme.Coexistent(objects[i].authority()); 

                    // вставить новую схему кодирования
                    encodables.add(redirectTagScheme.encode(this)); 
                }
                else {
                    // проверить тип органа регистрации
                    if (!(redirectTagScheme instanceof TagScheme.Coexistent))
                    {
                        // при ошибке выбросить исключение
                        throw new UnsupportedOperationException(); 
                    }
                    // выполнить преобразование типа
                    TagScheme.Coexistent tagScheme = (TagScheme.Coexistent)redirectTagScheme; 
                        
                    // проверить совпадение органа регистрации
                    if (!objects[i].authority().equals(tagScheme.schemeAuthority()))
                    {
                        // при ошибке выбросить исключение
                        throw new UnsupportedOperationException(); 
                    }
                }
                // закодировать объект
                encodables.add(objects[i].encode(redirectTagScheme)); 
            }
            // вернуть список закодированных представлений
            return encodables.toArray(new IEncodable[encodables.size()]); 
        }
        // раскодировать объекты
        @Override public DataObject[] decode(
            Authority outerAuthority, Iterable<IEncodable> encodables) throws IOException 
        {
            // скорректировать параметры
            if (outerAuthority == null) outerAuthority = schemeAuthority; 
            
            // создать список объектов
            List<DataObject> objects = new ArrayList<DataObject>(); TagScheme tagScheme = this;
        
            // для всех объектов
            for (IEncodable encodable : encodables)
            { 
                // указать тип объекта
                Tag tag = new Tag(encodable.tag(), encodable.pc()); 
            
                // при указании схемы объектов
                if (tag.equals(Tag.COEXISTENT_TAG_SCHEME))
                {
                    // проверить отсутствие переопределения схемы кодирования
                    if (tagScheme != this) throw new UnsupportedOperationException(); 
                    
                    // раскодировать новый орган регистрации
                    tagScheme = new TagScheme.Coexistent(encodable.content()); 
                }
            }
            // для всех объектов
            for (IEncodable encodable : encodables)
            { 
                // указать тип объекта
                Tag tag = new Tag(encodable.tag(), encodable.pc()); 
            
                // проверить отсутствие схемы объектов
                if (tag.equals(Tag.COEXISTENT_TAG_SCHEME)) continue; 
            
                // для шаблона межотраслевых объектов
                if (tag.equals(Tag.INTERINDUSTRY_TEMPLATE))
                {
                    // раскодировать шаблон
                    DataObjectTemplate template = new InterindustryTemplate(this, encodable.content()); 
                    
                    // добавить объекты в список
                    for (DataObject obj : template) objects.add(obj); 
                }
                // раскодировать объект
                else objects.add(tagScheme.decode(outerAuthority, encodable)); 
            }
            // вернуть список объектов
            return objects.toArray(new DataObject[objects.size()]); 
        }
        // раскодировать объекты
        @Override public DataObject decode(Authority outerAuthority, Tag tag, byte[] content) throws IOException
        {
            // скорректировать параметры
            if (outerAuthority == null) outerAuthority = schemeAuthority; 
            
            // 1) outerAuthority == schemeAuthority   (по умолчанию)
            // 2) outerAuthority == Authority.ISO7816 (внутри InterindustryTemplate)
            
            // для стандартных объектов ISO 8825
            if (tag.tagClass().equals(TagClass.UNIVERSAL))
            {
                // раскодировать межотраслевой объект
                return super.decodeISO7816(tag, content); 
            }
            // для объектов приложения
            else if (tag.tagClass().equals(TagClass.APPLICATION))
            {
                // для специальных составных объектов
                if (tag.equals(Tag.COEXISTENT_TAG_SCHEME   ) || 
                    tag.equals(Tag.INTERINDUSTRY_TEMPLATE  ) ||
                    tag.equals(Tag.FILE_CONTROL_PARAMETERS ) || 
                    tag.equals(Tag.FILE_MANAGEMENT_DATA    ) || 
                    tag.equals(Tag.FILE_CONTROL_INFORMATION) || 
                    tag.equals(Tag.SECURE_MESSAGING        ))
                {
                    // раскодировать межотраслевой объект
                    return super.decodeISO7816(tag, content); 
                }
                // для объектов ISO 7816
                if (schemeAuthority.equals(Authority.ISO7816) || 
                    outerAuthority .equals(Authority.ISO7816))
                {
                    // раскодировать межотраслевой объект
                    return super.decodeISO7816(tag, content); 
                }
                // для составных объектов
                if (tag.pc.equals(PC.CONSTRUCTED))
                {
                    // раскодировать составной объект
                    return new DataObjectTemplate(schemeAuthority, tag, this, content);  
                }
                else {
                    // раскодировать примитивный объект
                    return new DataObject(schemeAuthority, tag, content);   
                }
            }
            // для контекстных объектов
            else if (tag.tagClass().equals(TagClass.CONTEXT))
            {
                // для составных объектов
                if (tag.pc.equals(PC.CONSTRUCTED))
                {
                    // раскодировать составной объект
                    return new DataObjectTemplate(outerAuthority, tag, this, content); 
                }
                else {
                    // раскодировать примитивный объект
                    return new DataObject(outerAuthority, tag, content); 
                }
            }
            else {
                // для объектов ISO 7816
                if (schemeAuthority.equals(Authority.ISO7816) || 
                    outerAuthority .equals(Authority.ISO7816))
                {
                    // выбросить исключение
                    throw new UnsupportedOperationException(); 
                }
                // для составных объектов
                if (tag.pc.equals(PC.CONSTRUCTED))
                {
                    // раскодировать составной объект
                    return new DataObjectTemplate(schemeAuthority, tag, this, content);  
                }
                else {
                    // раскодировать примитивный объект
                    return new DataObject(schemeAuthority, tag, content);   
                }
            }
        }
    }
}
