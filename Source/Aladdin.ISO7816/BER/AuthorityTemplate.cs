using System;
using System.Collections.Generic;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Шаблон для немежотраслевых информационных объектов
    ///////////////////////////////////////////////////////////////////////////
    public class AuthorityTemplate : DataObjectTemplate
    {
        // раскодировать шаблон
        public static AuthorityTemplate Decode(Tag tag, TagScheme tagScheme, byte[] content)
        {
            // создать список объектов идентификации и список представлений объектов
            List<DataObject> authorityObjects = new List<DataObject>(); List<byte[]> encodeds = new List<byte[]>();
                
            // для всех внутренних объектов
            for (int offset = 0; offset < content.Length; )
            { 
                // раскодировать содержимое
                ASN1.IEncodable encodable = ASN1.Encodable.Decode(content, offset, content.Length - offset); 

                // получить тип объекта
                Tag encodableTag = new Tag(encodable.Tag, encodable.PC); 

                // для объекта идентификации
                if (encodable.Tag == ASN1.Tag.ObjectIdentifier)
                {
                    // раскодировать объект идентификации
                    authorityObjects.Add(new DataObject(Authority.ISO7816, encodable)); 
                }
                // для объекта идентификации
                else if (encodableTag == Aladdin.ISO7816.Tag.CountryIndicator)
                {
                    // раскодировать объект идентификации
                    authorityObjects.Add(new CountryIndicator(encodable.Content)); 
                }
                // для объекта идентификации
                else if (encodableTag == Aladdin.ISO7816.Tag.IssuerIndicator)
                {
                    // раскодировать объект идентификации
                    authorityObjects.Add(new IssuerIndicator(encodable.Content)); 
                }
                // для объекта идентификации
                else if (encodableTag == Aladdin.ISO7816.Tag.ApplicationIdentifier)
                {
                    // раскодировать объект идентификации
                    authorityObjects.Add(ApplicationIdentifier.Decode(encodable.Content)); 
                }
                // сохранить представление объекта
                else encodeds.Add(encodable.Encoded); 

                // перейти на следующий объект
                offset += encodable.Encoded.Length; 
            }
            // при наличии объектов регистрации 
            Authority authority = tagScheme.Authority; if (authorityObjects.Count != 0) 
            {
                // указать регистрационный орган
                authority = new Authority(authorityObjects);

                // удалить объекты регистрации
                content = Arrays.Concat(encodeds.ToArray()); 
            }
            // раскодировать шаблон
            return new AuthorityTemplate(authority, tag, tagScheme, content); 
        }
        // конструктор закодирования
        public AuthorityTemplate(Authority authority, Tag tag, params DataObject[] objects)
        
            // сохранить переданные параметры
            : base(authority, tag, objects) {}
        
        // конструктор раскодирования
        private AuthorityTemplate(Authority authority, Tag tag, TagScheme tagScheme, byte[] content)
        
            // сохранить переданные параметры
            : base(authority, tag, tagScheme, content) {} 

        ///////////////////////////////////////////////////////////////////////////
        // Закодировать объект
        ///////////////////////////////////////////////////////////////////////////
        public override ASN1.IEncodable Encode(TagScheme tagScheme)
        {
            // получить объекты идентификации
            DataObject[] authorityObjects = Authority.Objects; 

            // выделить память для закодированных представлений
            byte[][] encodeds = new byte[authorityObjects.Length + 1][];  

            // для всех объектов идентификации
            for (int i = 0; i < authorityObjects.Length; i++) 
            {
                // получить закодированные представления
                encodeds[i] = authorityObjects[i].Encode(tagScheme).Encoded; 
            }
            // вызвать базовую функцию
            encodeds[authorityObjects.Length] = base.Encode(tagScheme).Content; 

            // закодировать объект
            return ASN1.Encodable.Encode(Tag.AsnTag, Tag.PC, Arrays.Concat(encodeds)); 
        }
    }
}
