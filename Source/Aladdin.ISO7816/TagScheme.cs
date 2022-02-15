using System; 
using System.Collections.Generic; 

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Источник распределения тэгов 
    ///////////////////////////////////////////////////////////////////////////
    public abstract class TagScheme : DataObjectTemplate
    {
        // схема распределения тегов по умолчанию
        public static readonly TagScheme Default = new Standard(); 
    
        // раскодировать источник распределения тэгов 
        public static TagScheme DecodeTagScheme(Tag tag, byte[] content)
        {
            // создать список объектов
            List<DataObject> objects = new List<DataObject>(); 
            
            // раскодировать закодированное представление
            ASN1.IEncodable encodable = ASN1.Encodable.Decode(content, 0, content.Length); 
            
            // раскодировать объект
            DataObject obj = TagScheme.Default.Decode(Authority.ISO7816, encodable); 
            
            // добавить объект в список и перейти на следующий объект
            objects.Add(obj); int offset = encodable.Encoded.Length; 
        
            // для всех внутренних объектов
            for (; offset < content.Length; offset += encodable.Encoded.Length)
            { 
                // раскодировать закодированное представление
                encodable = ASN1.Encodable.Decode(content, offset, content.Length - offset); 

                // раскодировать объект и добавить его в список
                objects.Add(TagScheme.Default.Decode(Authority.ISO7816, encodable)); 
            }
            if (tag == Tag.CoexistentTagScheme)
            {
                // вернуть способ кодирования
                return new TagScheme.Coexistent(new Authority(objects)); 
            }
            else {
                // указать тип объекта
                Tag encodableTag = new Tag(encodable.Tag, encodable.PC); 

                // проверить тип представления
                if (encodableTag != Tag.Context(0x00, ASN1.PC.Primitive))
                {
                    // вернуть способ кодирования
                    return new TagScheme.Compatible(new Authority(objects)); 
                }
                // создать список объектов органа регистрации
                DataObject[] authorityObjects = new DataObject[objects.Count - 1]; 
            
                // заполнить список объектов органа регистрации
                for (int i = 1; i < objects.Count; i++) authorityObjects[i - 1] = objects[i]; 

                // вернуть способ кодирования
                return new TagScheme.Standard(new Authority(authorityObjects), objects.ToArray()); 
            }
        }
        // конструктор закодирования
        protected TagScheme(Tag tag, params DataObject[] objects) 
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, tag, objects) {}  
        
        // конструктор раскодирования
        protected TagScheme(Tag tag, byte[] content) 
         
            // сохранить переданные параметры
            : base(Authority.ISO7816, tag, TagScheme.Default, content) {} 
        
        // закодировать объекты
        public abstract ASN1.IEncodable[] Encode(DataObject[] objects); 
        // раскодировать объекты
        public abstract DataObject[] Decode(
            Authority outerAuthority, IEnumerable<ASN1.IEncodable> encodables
        ); 
        // раскодировать объект
        public DataObject Decode(Authority outerAuthority, ASN1.IEncodable encodable)
        {
            // указать тип объекта
            Tag tag = new Tag(encodable.Tag, encodable.PC); 

            // раскодировать объект
            return Decode(outerAuthority, tag, encodable.Content); 
        }
        // раскодировать объект
        public abstract DataObject Decode(Authority outerAuthority, Tag tag, byte[] content); 
        
        // раскодировать межотраслевой объект
        protected DataObject DecodeISO7816(Tag tag, byte[] content)
        {
            // для сосуществующей схемы кодирования
            if (tag == Tag.CoexistentTagScheme)
            {
                // раскодировать сосуществующую схему кодирования
                return new TagScheme.Coexistent(content); 
            }
            // для шаблона межотраслевых объектов
            if (tag == Tag.InterindustryTemplate)
            {
                // раскодировать шаблон межлотраслевых объектов
                return new BER.InterindustryTemplate(this, content); 
            }
            // для специальных составных объектов
            if (tag == Tag.FileControlParameters)
            {
                // раскодировать специальный составной объект
                return new BER.FileControlParameters(this, content); 
            }
            // для специальных составных объектов
            if (tag == Tag.FileManagementData)
            {
                // раскодировать специальный составной объект
                return new BER.FileManagementData(this, content); 
            }
            // для специальных составных объектов
            if (tag == Tag.FileControlInformation)
            {
                // раскодировать специальный составной объект
                return new BER.FileControlInformation(this, content); 
            }
            // для специальных составных объектов
            if (tag == Tag.SecureMessaging)
            {
                // раскодировать специальный составной объект
                return new BER.SecureMessaging(this, content); 
            }
            // для составных объектов
            if (tag.PC == ASN1.PC.Constructed)
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
        public class Standard : TagScheme
        {
            // орган регистрации внутренних тегов
            private Authority subAuthority; 
        
            // конструктор закодирования
            internal Standard() : this(null) {}

            // конструктор закодирования
            internal Standard(Authority subAuthority, params DataObject[] objects) 
            
                // сохранить переданные параметры
                : base(Tag.CompatibleTagScheme, objects)  
            {
                // сохранить переданные параметры
                this.subAuthority = subAuthority;
            }
            // закодировать объекты
            public override ASN1.IEncodable[] Encode(DataObject[] objects)
            {
                // создать список закодированных представлений
                List<ASN1.IEncodable> encodables = new List<ASN1.IEncodable>(); 
            
                // новая схема кодирования объектов
                TagScheme redirectTagScheme = null; 
            
                // для всех объектов
                foreach (DataObject obj in objects)
                {
                    // для межотраслевых информационных объектов
                    if (obj.Authority.Equals(Authority.ISO7816))
                    {
                        // закодировать объект
                        encodables.Add(obj.Encode(this)); continue; 
                    }
                    // при совпадении органа регистрации
                    if (subAuthority != null && obj.Authority.Equals(subAuthority))
                    {
                        // сохранить схему кодирования
                        if (redirectTagScheme == null) redirectTagScheme = this; 
                    
                         // проверить совпадение схемы кодирования
                        else if (redirectTagScheme != this)
                        {
                            // при ошибке выбросить исключение
                            throw new NotSupportedException(); 
                        }
                    }
                    // при отсутствии переопределения схемы кодирования
                    else if (redirectTagScheme == null)
                    {
                        // создать описание новой схемы кодирования
                        redirectTagScheme = new TagScheme.Coexistent(obj.Authority); 

                        // вставить новую схему кодирования
                        encodables.Add(redirectTagScheme.Encode(this)); 
                    }
                    else {
                        // проверить тип органа регистрации
                        if (!(redirectTagScheme is TagScheme.Coexistent))
                        {
                            // при ошибке выбросить исключение
                            throw new NotSupportedException(); 
                        }
                        // выполнить преобразование типа
                        TagScheme.Coexistent tagScheme = (TagScheme.Coexistent)redirectTagScheme; 
                        
                        // проверить совпадение органа регистрации
                        if (!obj.Authority.Equals(tagScheme.SchemeAuthority))
                        {
                            // при ошибке выбросить исключение
                            throw new NotSupportedException(); 
                        }
                    }
                    // закодировать объект
                    encodables.Add(obj.Encode(redirectTagScheme)); 
                }
                // вернуть список закодированных представлений
                return encodables.ToArray(); 
            }
            // раскодировать объекты
            public override DataObject[] Decode(Authority outerAuthority, IEnumerable<ASN1.IEncodable> encodables) 
            {
                // скорректировать параметры
                if (outerAuthority == null) outerAuthority = (subAuthority != null) ? subAuthority : Authority.ISO7816; 
            
                // создать список объектов
                List<DataObject> objects = new List<DataObject>(); TagScheme tagScheme = this;
            
                // для всех объектов
                foreach (ASN1.IEncodable encodable in encodables)
                { 
                    // указать тип объекта
                    Tag tag = new Tag(encodable.Tag, encodable.PC); 
            
                    // при указании схемы объектов
                    if (tag == Tag.CoexistentTagScheme || tag == Tag.CompatibleTagScheme)
                    {
                        // проверить отсутствие переопределения схемы кодирования
                        if (tagScheme != this) throw new NotSupportedException(); 
                    
                        // раскодировать новый орган регистрации
                        tagScheme = TagScheme.DecodeTagScheme(tag, encodable.Content); 
                    }
                }
                // для всех объектов
                foreach (ASN1.IEncodable encodable in encodables)
                { 
                    // указать тип объекта
                    Tag tag = new Tag(encodable.Tag, encodable.PC); 
            
                    // проверить отсутствие схемы объектов
                    if (tag == Tag.CoexistentTagScheme) continue; 
                    if (tag == Tag.CompatibleTagScheme) continue; 
            
                    // для шаблона межотраслевых объектов
                    if (tag == Tag.InterindustryTemplate)
                    {
                        // раскодировать шаблон
                        DataObjectTemplate template = new BER.InterindustryTemplate(
                            this, encodable.Content
                        ); 
                        // добавить объекты в список
                        objects.AddRange(template); 
                    }
                    // раскодировать объект
                    else objects.Add(tagScheme.Decode(outerAuthority, encodable)); 
                }
                // вернуть список объектов
                return objects.ToArray(); 
            }
            // раскодировать объекты
            public override DataObject Decode(Authority outerAuthority, Tag tag, byte[] content)
            {
                // скорректировать параметры
                if (outerAuthority == null) outerAuthority = (subAuthority != null) ? subAuthority : Authority.ISO7816; 
            
                // 1) outerAuthority == Authority.ISO7816 (по умолчанию)
                // 2) outerAuthority == subAuthority      (для длинных тэгов)
            
                // для стандартных объектов ISO 8825
                if (tag.Class == ASN1.TagClass.Universal)
                {
                    // раскодировать межотраслевой объект
                    return base.DecodeISO7816(tag, content); 
                }
                // для объектов приложения
                else if (tag.Class == ASN1.TagClass.Application)
                {
                    // для межотраслевых объектов
                    if (tag.Value < 128 || 512 <= tag.Value)
                    {
                        // раскодировать межотраслевой объект
                        return base.DecodeISO7816(tag, content); 
                    }
                    else { 
                        // проверить наличие органа регистрации
                        if (subAuthority == null) throw new NotSupportedException(); 
                
                        // для составных объектов
                        if (tag.PC == ASN1.PC.Constructed)
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
                else if (tag.Class == ASN1.TagClass.Context)
                {
                    // для составных объектов
                    if (tag.PC == ASN1.PC.Constructed)
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
                else throw new NotSupportedException(); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Источник распределения совместимых тэгов 
        ///////////////////////////////////////////////////////////////////////
        public class Compatible : TagScheme
        {
            // орган регистрации тегов
            private Authority schemeAuthority; 
        
            // конструктор закодирования
            public Compatible(Authority schemeAuthority) 
            
                // сохранить переданные параметры
                : base(Tag.CompatibleTagScheme, schemeAuthority.Objects)   
            {
                // сохранить переданные параметры
                this.schemeAuthority = schemeAuthority;
            }
            // орган регистрации тегов
            public Authority SchemeAuthority { get { return schemeAuthority; }} 

            // закодировать объекты
            public override ASN1.IEncodable[] Encode(DataObject[] objects)
            {
                // создать список закодированных представлений
                List<ASN1.IEncodable> encodables = new List<ASN1.IEncodable>(); 
            
                // новый схема кодирования объектов
                TagScheme redirectTagScheme = null; 
            
                // для всех объектов
                foreach (DataObject obj in objects)
                {
                    // для шаблона немежотраслевых информационных объектов
                    if (obj.Tag == Tag.AuthorityTemplate0 || obj.Tag == Tag.AuthorityTemplate1 || 
                        obj.Tag == Tag.AuthorityTemplate2 || 
                        obj.Tag == Tag.AuthorityTemplate4 || obj.Tag == Tag.AuthorityTemplate5 || 
                        obj.Tag == Tag.AuthorityTemplate6 || obj.Tag == Tag.AuthorityTemplate7)
                    {
                        // указать используемую схему кодирования
                        if (redirectTagScheme == null) redirectTagScheme = this; 
                        
                         // проверить совпадение схемы кодирования
                        else if (redirectTagScheme != this)
                        {
                            // при ошибке выбросить исключение
                            throw new NotSupportedException(); 
                        }
                        // закодировать объект
                        encodables.Add(obj.Encode(this)); continue; 
                    }
                    // для межотраслевых информационных объектов
                    if (obj.Authority.Equals(Authority.ISO7816))
                    {
                        // закодировать объект
                        encodables.Add(obj.Encode(this)); continue; 
                    }
                    // при совпадении органа регистрации
                    if (obj.Authority.Equals(schemeAuthority))
                    {
                        // указать используемую схему кодирования
                        if (redirectTagScheme == null) redirectTagScheme = this; 
                        
                         // проверить совпадение схемы кодирования
                        else if (redirectTagScheme != this)
                        {
                            // при ошибке выбросить исключение
                            throw new NotSupportedException(); 
                        }
                    }
                    // при отсутствии переопределения схемы кодирования
                    else if (redirectTagScheme == null)
                    {
                        // создать описание новой схемы кодирования
                        redirectTagScheme = new TagScheme.Coexistent(obj.Authority); 

                        // вставить новую схему кодирования
                        encodables.Add(redirectTagScheme.Encode(this)); 
                    }
                    else {
                        // проверить тип органа регистрации
                        if (!(redirectTagScheme is TagScheme.Coexistent))
                        {
                            // при ошибке выбросить исключение
                            throw new NotSupportedException(); 
                        }
                        // выполнить преобразование типа
                        TagScheme.Coexistent tagScheme = (TagScheme.Coexistent)redirectTagScheme; 
                        
                        // проверить совпадение органа регистрации
                        if (!obj.Authority.Equals(tagScheme.SchemeAuthority))
                        {
                            // при ошибке выбросить исключение
                            throw new NotSupportedException(); 
                        }
                    }
                    // закодировать объект
                    encodables.Add(obj.Encode(redirectTagScheme)); 
                }
                // вернуть список закодированных представлений
                return encodables.ToArray(); 
            }
            // раскодировать объекты
            public override DataObject[] Decode(Authority outerAuthority, IEnumerable<ASN1.IEncodable> encodables)
            {
                // скорректировать параметры
                if (outerAuthority == null) outerAuthority = schemeAuthority; 
            
                // создать список объектов
                List<DataObject> objects = new List<DataObject>(); TagScheme tagScheme = this;
            
                // для всех объектов
                foreach (ASN1.IEncodable encodable in encodables)
                { 
                    // указать тип объекта
                    Tag tag = new Tag(encodable.Tag, encodable.PC); 
            
                    // при указании схемы объектов
                    if (tag == Tag.CoexistentTagScheme || tag == Tag.CompatibleTagScheme)
                    {
                        // проверить отсутствие переопределения схемы кодирования
                        if (tagScheme != this) throw new NotSupportedException(); 
                    
                        // раскодировать новый орган регистрации
                        tagScheme = TagScheme.DecodeTagScheme(tag, encodable.Content); 
                    }
                }
                // для всех объектов
                foreach (ASN1.IEncodable encodable in encodables)
                { 
                    // указать тип объекта
                    Tag tag = new Tag(encodable.Tag, encodable.PC); 
            
                    // проверить отсутствие схемы объектов
                    if (tag == Tag.CoexistentTagScheme) continue; 
                    if (tag == Tag.CompatibleTagScheme) continue; 
            
                    // для шаблона межотраслевых объектов
                    if (tag == Tag.InterindustryTemplate)
                    {
                        // раскодировать шаблон
                        DataObjectTemplate template = new BER.InterindustryTemplate(
                            this, encodable.Content
                        ); 
                        // добавить объекты в список
                        objects.AddRange(template); 
                    }
                    // раскодировать объект
                    else objects.Add(tagScheme.Decode(outerAuthority, encodable)); 
                }
                // вернуть список объектов
                return objects.ToArray(); 
            }
            // раскодировать объекты
            public override DataObject Decode(Authority outerAuthority, Tag tag, byte[] content) 
            {
                // скорректировать параметры
                if (outerAuthority == null) outerAuthority = schemeAuthority; 
            
                // 1) outerAuthority == Authority.ISO7816            (по умолчанию)
                // 2) outerAuthority == schemeAuthority              (в AuthorityTemplate без переопределения)
                // 3) outerAuthority == AuthorityTemplate.Authority  (в AuthorityTemplate c переопределением)
            
                // для стандартных объектов ISO 8825
                if (tag.Class == ASN1.TagClass.Universal)
                {
                    // раскодировать межотраслевой объект
                    return base.DecodeISO7816(tag, content); 
                }
                // для объектов приложения
                else if (tag.Class == ASN1.TagClass.Application)
                {
                    // для шаблона немежотраслевых информационных объектов
                    if (tag == Tag.AuthorityTemplate0 || tag == Tag.AuthorityTemplate1 || 
                        tag == Tag.AuthorityTemplate2 || 
                        tag == Tag.AuthorityTemplate4 || tag == Tag.AuthorityTemplate5 || 
                        tag == Tag.AuthorityTemplate6 || tag == Tag.AuthorityTemplate7)
                    {
                        // раскодировать шаблон немежотраслевых информационных объектов
                        return BER.AuthorityTemplate.Decode(tag, this, content); 
                    }
                    // раскодировать межотраслевой объект
                    else return base.DecodeISO7816(tag, content); 
                }
                // для контекстных объектов
                else if (tag.Class == ASN1.TagClass.Context)
                {
                    // для составных объектов
                    if (tag.PC == ASN1.PC.Constructed)
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
                else throw new NotSupportedException(); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Источник распределения сосуществующих тэгов 
        ///////////////////////////////////////////////////////////////////////
        public class Coexistent : TagScheme
        {
            // орган регистрации тегов
            private Authority schemeAuthority; 
        
            // конструктор закодирования
            public Coexistent(Authority schemeAuthority) 
            
                // сохранить переданные параметры
                : base(Tag.CoexistentTagScheme, schemeAuthority.Objects)  
            {
                // сохранить переданные параметры
                this.schemeAuthority = schemeAuthority;
            }
            // конструктор раскодирования
            public Coexistent(byte[] content) 
             
                // сохранить переданные параметры
                : base(Tag.CoexistentTagScheme, content) 
            {
                // раскодировать орган регистрации тегов
                schemeAuthority = new Authority(this); 
            }
            // орган регистрации тегов
            public Authority SchemeAuthority { get { return schemeAuthority; }} 

            // закодировать объекты
            public override ASN1.IEncodable[] Encode(DataObject[] objects)
            {
                // создать список закодированных представлений
                List<ASN1.IEncodable> encodables = new List<ASN1.IEncodable>(); 
            
                // новый схема кодирования объектов
                TagScheme redirectTagScheme = null; 
            
                // для всех объектов
                for (int i = 0; i < objects.Length; i++)
                {
                    // для специальных объектов
                    if (objects[i].Tag == Tag.CoexistentTagScheme    || 
                        objects[i].Tag == Tag.InterindustryTemplate  || 
                        objects[i].Tag == Tag.FileControlParameters  || 
                        objects[i].Tag == Tag.FileManagementData     || 
                        objects[i].Tag == Tag.FileControlInformation || 
                        objects[i].Tag == Tag.SecureMessaging       )
                    {
                        // закодировать объект
                        encodables.Add(objects[i].Encode(this)); continue; 
                    }
                    // создать список межотраслевых объектов
                    List<DataObject> objsISO7816 = new List<DataObject>(); 
                
                    // для межотраслевых объектов
                    for (; i < objects.Length; i++)
                    {
                        // проверить регистрирующий орган
                        if (!objects[i].Authority.Equals(Authority.ISO7816)) break;
                    
                        // добавить объект в список
                        objsISO7816.Add(objects[i]); 
                    }
                    // при наличии межотраслевых объектов
                    if (objsISO7816.Count > 0) 
                    { 
                        // создать шаблон межотраслевых объектов
                        BER.InterindustryTemplate template = 
                            new BER.InterindustryTemplate(objsISO7816.ToArray()); 
                    
                        // закодировать шаблон
                        encodables.Add(template.Encode(this)); continue; 
                    }
                    // при совпадении органа регистрации
                    if (objects[i].Authority.Equals(schemeAuthority))
                    {
                        // указать используемую схему кодирования
                        if (redirectTagScheme == null) redirectTagScheme = this; 
                        
                         // проверить совпадение схемы кодирования
                        else if (redirectTagScheme != this)
                        {
                            // при ошибке выбросить исключение
                            throw new NotSupportedException(); 
                        }
                    }
                    // при отсутствии переопределения схемы кодирования
                    else if (redirectTagScheme == null)
                    {
                        // создать описание новой схемы кодирования
                        redirectTagScheme = new TagScheme.Coexistent(objects[i].Authority); 

                        // вставить новую схему кодирования
                        encodables.Add(redirectTagScheme.Encode(this)); 
                    }
                    else {
                        // проверить тип органа регистрации
                        if (!(redirectTagScheme is TagScheme.Coexistent))
                        {
                            // при ошибке выбросить исключение
                            throw new NotSupportedException(); 
                        }
                        // выполнить преобразование типа
                        TagScheme.Coexistent tagScheme = (TagScheme.Coexistent)redirectTagScheme; 
                        
                        // проверить совпадение органа регистрации
                        if (!objects[i].Authority.Equals(tagScheme.SchemeAuthority))
                        {
                            // при ошибке выбросить исключение
                            throw new NotSupportedException(); 
                        }
                    }
                    // закодировать объект
                    encodables.Add(objects[i].Encode(redirectTagScheme)); 
                }
                // вернуть список закодированных представлений
                return encodables.ToArray(); 
            }
            // раскодировать объекты
            public override DataObject[] Decode(Authority outerAuthority, IEnumerable<ASN1.IEncodable> encodables)
            {
                // скорректировать параметры
                if (outerAuthority == null) outerAuthority = schemeAuthority; 
            
                // создать список объектов
                List<DataObject> objects = new List<DataObject>(); TagScheme tagScheme = this;
        
                // для всех объектов
                foreach (ASN1.IEncodable encodable in encodables)
                { 
                    // указать тип объекта
                    Tag tag = new Tag(encodable.Tag, encodable.PC); 
            
                    // при указании схемы объектов
                    if (tag == Tag.CoexistentTagScheme)
                    {
                        // проверить отсутствие переопределения схемы кодирования
                        if (tagScheme != this) throw new NotSupportedException(); 
                    
                        // раскодировать новый орган регистрации
                        tagScheme = new TagScheme.Coexistent(encodable.Content); 
                    }
                }
                // для всех объектов
                foreach (ASN1.IEncodable encodable in encodables)
                { 
                    // указать тип объекта
                    Tag tag = new Tag(encodable.Tag, encodable.PC); 
            
                    // проверить отсутствие схемы объектов
                    if (tag == Tag.CoexistentTagScheme) continue; 
            
                    // для шаблона межотраслевых объектов
                    if (tag == Tag.InterindustryTemplate)
                    {
                        // раскодировать шаблон
                        DataObjectTemplate template = new BER.InterindustryTemplate(
                            this, encodable.Content
                        ); 
                        // добавить объекты в список
                        objects.AddRange(template); 
                    }
                    // раскодировать объект
                    else objects.Add(tagScheme.Decode(outerAuthority, encodable)); 
                }
                // вернуть список объектов
                return objects.ToArray(); 
            }
            // раскодировать объекты
            public override DataObject Decode(Authority outerAuthority, Tag tag, byte[] content)
            {
                // скорректировать параметры
                if (outerAuthority == null) outerAuthority = schemeAuthority; 
            
                // 1) outerAuthority == schemeAuthority   (по умолчанию)
                // 2) outerAuthority == Authority.ISO7816 (внутри InterindustryTemplate)
            
                // для стандартных объектов ISO 8825
                if (tag.Class == ASN1.TagClass.Universal)
                {
                    // раскодировать межотраслевой объект
                    return base.DecodeISO7816(tag, content); 
                }
                // для объектов приложения
                else if (tag.Class == ASN1.TagClass.Application)
                {
                    // для специальных составных объектов
                    if (tag == Tag.CoexistentTagScheme    || 
                        tag == Tag.InterindustryTemplate  ||
                        tag == Tag.FileControlParameters  || 
                        tag == Tag.FileManagementData     || 
                        tag == Tag.FileControlInformation || 
                        tag == Tag.SecureMessaging       )
                    {
                        // раскодировать межотраслевой объект
                        return base.DecodeISO7816(tag, content); 
                    }
                    // для объектов ISO 7816
                    if (schemeAuthority.Equals(Authority.ISO7816) || 
                        outerAuthority .Equals(Authority.ISO7816))
                    {
                        // раскодировать межотраслевой объект
                        return base.DecodeISO7816(tag, content); 
                    }
                    // для составных объектов
                    if (tag.PC == ASN1.PC.Constructed)
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
                else if (tag.Class == ASN1.TagClass.Context)
                {
                    // для составных объектов
                    if (tag.PC == ASN1.PC.Constructed)
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
                    if (schemeAuthority.Equals(Authority.ISO7816) || 
                        outerAuthority .Equals(Authority.ISO7816))
                    {
                        // выбросить исключение
                        throw new NotSupportedException(); 
                    }
                    // для составных объектов
                    if (tag.PC == ASN1.PC.Constructed)
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
}
