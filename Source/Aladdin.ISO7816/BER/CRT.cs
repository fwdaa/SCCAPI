using System;
using System.IO;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////////
    // Описание параметров алгоритма
    ///////////////////////////////////////////////////////////////////////////////
    public class CRT : DataObjectTemplate
    {
        // конструктор закодирования
        public CRT(Tag tag, params DataObject[] objects)

            // сохранить переданные параметры
            : base(Authority.ISO7816, tag, objects) 
        {
            // проверить наличие идентификатора
            if (this[Tag.Context(0x00, ASN1.PC.Primitive)].Length != 1) 
            {
                // при ошибке выбросить исключение
                throw new ArgumentException(); 
            }
        }
        // конструктор раскодирования
        public CRT(Tag tag, TagScheme tagScheme, byte[] content) 
            
            // проверить корректность данных
            : base(Authority.ISO7816, tag, tagScheme, content)
        {
            // проверить наличие идентификатора
            if (this[Tag.Context(0x00, ASN1.PC.Primitive)].Length != 1) 
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException(); 
            }
        } 
        // идентификатор алгоритма
        public byte[] MechanismReference { get  
        { 
            // идентификатор алгоритма
            return this[Tag.Context(0x00, ASN1.PC.Primitive)][0].Content; 
        }}
        // способ использования шаблона
        public byte UsageQualifier { get  
        {
            // получить способ использования шаблона
            DataObject[] objs = this[Tag.Context(0x15, ASN1.PC.Primitive)]; 
        
            // проверить наличие способа использования
            if (objs.Length == 0 || objs[0].Content.Length == 0) return 0; 
        
            // вернуть способ использования шаблона
            return objs[0].Content[0]; 
        }}
        ///////////////////////////////////////////////////////////////////////////
        // Описание параметров алгоритма аутентификации
        ///////////////////////////////////////////////////////////////////////////
        public class AT : CRT
        {
            // конструктор закодирования
            public AT(Tag tag, params DataObject[] objects) : base(tag, objects)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x04, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x05, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
            }
            // конструктор раскодирования
            public AT(Tag tag, TagScheme tagScheme, byte[] content) : base(tag, tagScheme, content)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x04, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x05, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
            } 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Описание параметров алгоритма хэширования
        ///////////////////////////////////////////////////////////////////////////
        public class HT : CRT
        {
            // конструктор закодирования
            public HT(Tag tag, params DataObject[] objects) : base(tag, objects)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x0A, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x0B, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
            }
            // конструктор раскодирования
            public HT(Tag tag, TagScheme tagScheme, byte[] content) : base(tag, tagScheme, content)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x0A, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x0B, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
            } 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Описание параметров алгоритма выработки контрольной суммы
        ///////////////////////////////////////////////////////////////////////////
        public class CCT : CRT
        {
            // конструктор закодирования
            public CCT(Tag tag, params DataObject[] objects) : base(tag, objects)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x14, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x15, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
            }
            // конструктор раскодирования
            public CCT(Tag tag, TagScheme tagScheme, byte[] content) : base(tag, tagScheme, content)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x14, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x15, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
            } 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Описание параметров алгоритма шифрования (симметричного или асимметричного)
        ///////////////////////////////////////////////////////////////////////////
        public class CT : CRT
        {
            // конструктор закодирования
            public CT(Tag tag, params DataObject[] objects) : base(tag, objects)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x18, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x19, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
            }
            // конструктор раскодирования
            public CT(Tag tag, TagScheme tagScheme, byte[] content) : base(tag, tagScheme, content)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x18, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x19, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
            } 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Описание параметров алгоритма подписи
        ///////////////////////////////////////////////////////////////////////////
        public class DST : CRT
        {
            // конструктор закодирования
            public DST(Tag tag, params DataObject[] objects) : base(tag, objects)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x16, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x17, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
            }
            // конструктор раскодирования
            public DST(Tag tag, TagScheme tagScheme, byte[] content) : base(tag, tagScheme, content)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x16, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x17, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
            } 
        }
        ///////////////////////////////////////////////////////////////////////////
        // Описание параметров алгоритма согласования ключа
        ///////////////////////////////////////////////////////////////////////////
        public class KAT : CRT
        {
            // конструктор закодирования
            public KAT(Tag tag, params DataObject[] objects) : base(tag, objects)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x06, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x07, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new ArgumentException(); 
                }
            }
            // конструктор раскодирования
            public KAT(Tag tag, TagScheme tagScheme, byte[] content) : base(tag, tagScheme, content)
            {    
                // проверить тип параметров
                if (tag != Tag.Context(0x06, ASN1.PC.Constructed) && 
                    tag != Tag.Context(0x07, ASN1.PC.Constructed))
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
            } 
        }
    }
}
