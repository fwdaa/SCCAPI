using System;
using System.IO;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Шаблон безопасной среды (0x7B)
    ///////////////////////////////////////////////////////////////////////////
    public class SE : DataObjectTemplate
    {
        // конструктор закодирования
        public SE(params DataObject[] objects) 
             
            // сохранить переданные параметры
            : base(Authority.ISO7816, Tag.SecurityEnvironmentTemplate, objects) 
        {
            // получить идентификатор криптографической среды
            DataObject[] objs = this[Tag.Context(0x00, ASN1.PC.Primitive)]; 
        
            // проверить наличие идентификатора
            if (objs.Length != 1 || objs[0].Content.Length != 1)
            {
                // при ошибке выбросить исключение
                throw new ArgumentException();
            }
        }
        // конструктор раскодирования
        public SE(TagScheme tagScheme, byte[] content) 
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, Tag.SecurityEnvironmentTemplate, tagScheme, content) 
        {
            // получить идентификатор криптографической среды
            DataObject[] objs = this[Tag.Context(0x00, ASN1.PC.Primitive)]; 
        
            // проверить наличие идентификатора
            if (objs.Length != 1 || objs[0].Content.Length != 1)
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException();
            }
        }
        // идентификатор криптографической среды
        public int ID { get  
        {
            // получить требуемый объект
            DataObject obj = this[Tag.Context(0x14, ASN1.PC.Primitive)][0]; 
        
            // раскодировать идентификатор
            return obj.Content[0]; 
        }}
        // информация о состоянии
        public LifeCycle LifeCycle { get 
        {
            // указать тип объекта
            Tag tag = Tag.Context(0x0A, ASN1.PC.Primitive); 
        
            // получить требуемые объекты
            DataObject[] objs = this[tag]; if (objs.Length == 0) return null; 
        
            // раскодировать объект
            return new LifeCycle(tag, objs[0].Content); 
        }}
        // описание идентификаторов алгоритмов
        public MechanismID[] MechanismIDs(TagScheme tagScheme)
        {
            // получить требуемые объекты
            DataObject[] objs = this[Tag.Context(0x0C, ASN1.PC.Constructed)]; 

            // выделить список требуемого размера
            MechanismID[] mechanismsIDs = new MechanismID[objs.Length]; 
        
            // для всех объектов
            for (int i = 0; i < objs.Length; i++)
            {
                // раскодировать объект
                mechanismsIDs[i] = new MechanismID(tagScheme, objs[i].Content);
            }
            // вернуть список объектов
            return mechanismsIDs; 
        }
        // получить параметры алгоритма
        public  CRT.AT AuthenticationParameters(TagScheme tagScheme)
        {
            // указать тип объекта
            Tag tag = Tag.Context(0x04, ASN1.PC.Constructed); 
        
            // получить требуемые объекты
            DataObject[] objs = this[tag]; if (objs.Length == 0) return null; 
        
            // раскодировать объект
            return new CRT.AT(tag, tagScheme, objs[0].Content); 
        }
        // получить параметры алгоритма
        public CRT.HT HashParameters(TagScheme tagScheme) 
        {
            // указать тип объекта
            Tag tag = Tag.Context(0x0A, ASN1.PC.Constructed); 
        
            // получить требуемые объекты
            DataObject[] objs = this[tag]; if (objs.Length == 0) return null; 
        
            // раскодировать объект
            return new CRT.HT(tag, tagScheme, objs[0].Content); 
        }
        // получить параметры алгоритма
        public CRT.CCT MacParameters(TagScheme tagScheme) 
        {
            // указать тип объекта
            Tag tag = Tag.Context(0x14, ASN1.PC.Constructed); 
        
            // получить требуемые объекты
            DataObject[] objs = this[tag]; if (objs.Length == 0) return null; 
        
            // раскодировать объект
            return new CRT.CCT(tag, tagScheme, objs[0].Content); 
        }
        // получить параметры алгоритма
        public CRT.CT CipherParameters(TagScheme tagScheme) 
        {
            // указать тип объекта
            Tag tag = Tag.Context(0x18, ASN1.PC.Constructed); 
        
            // получить требуемые объекты
            DataObject[] objs = this[tag]; if (objs.Length == 0) return null; 
        
            // раскодировать объект
            return new CRT.CT(tag, tagScheme, objs[0].Content); 
        }
        // получить параметры алгоритма
        public CRT.DST SignParameters(TagScheme tagScheme) 
        {
            // указать тип объекта
            Tag tag = Tag.Context(0x16, ASN1.PC.Constructed); 
        
            // получить требуемые объекты
            DataObject[] objs = this[tag]; if (objs.Length == 0) return null; 
        
            // раскодировать объект
            return new CRT.DST(tag, tagScheme, objs[0].Content); 
        }
        // получить параметры алгоритма
        public CRT.KAT KeyAgreementParameters(TagScheme tagScheme) 
        {
            // указать тип объекта
            Tag tag = Tag.Context(0x06, ASN1.PC.Constructed); 
        
            // получить требуемые объекты
            DataObject[] objs = this[tag]; if (objs.Length == 0) return null; 
        
            // раскодировать объект
            return new CRT.KAT(tag, tagScheme, objs[0].Content); 
        }
    }
}
