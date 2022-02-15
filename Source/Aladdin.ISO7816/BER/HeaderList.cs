using System;
using System.Collections.Generic;
using System.IO;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Список заголовков (0x5D)
    ///////////////////////////////////////////////////////////////////////////
    public class HeaderList : DataObject
    {
        // список заголовков
        public readonly Header[] headers; 

        // конструктор закодирования 
        public HeaderList(params Header[] headers) 
         
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.HeaderList) { this.headers = headers; } 

        // конструктор раскодирования
        public HeaderList(byte[] content) 
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.HeaderList, content) 
        {
            // создать пустой список заголовков
            List<Header> headers = new List<Header>(); 
        
            // для всех внутренних объектов
            for (int offset = 0; offset < content.Length; )
            { 
                // раскодировать заголовок
                Header header = Header.Decode(
                    content, offset, content.Length - offset
                ); 
                // перейти на следующий объект
                headers.Add(header); offset += header.Encoded.Length;
            }
            // сохранить раскодированные объекты
            this.headers = headers.ToArray(); 
        }
        // закодированное представление
        public override byte[] Content { get 
        {
            // выделить память для закодированных представлений
            byte[][] encodeds = new byte[headers.Length][];  

            // для всех заголовков
            for (int i = 0; i < headers.Length; i++) 
            {
                // получить закодированное представление
                encodeds[i] = headers[i].Encoded;
            }
            // объединить закодированные представления
            return Arrays.Concat(encodeds); 
        }}
        // извлечь требуемые поля из объектов
        public ASN1.IEncodable[] Apply(ASN1.IEncodable[] encodables)
        {
            // создать список совпавших объектов
            ASN1.IEncodable[] matches = new ASN1.IEncodable[headers.Length]; 
        
            // для всех заголовков
            for (int i = 0, index = 0; i < headers.Length; i++)
            {
                // для всех представлений
                for (int j = index; j < encodables.Length; j++)
                {
                    // извлечь тип объекта
                    Tag tag = new Tag(encodables[j].Tag, encodables[j].PC);
            
                    // проверить совпадение типа
                    if (headers[i].Tag != tag) continue; index = j + 1; 
                    
                    // извлечь требуемые поля из объекта
                    ASN1.IEncodable matched = headers[i].Apply(encodables[j]); 
                    
                    // добавить представление в список
                    if (matched != null) matches[i] = matched; break;
                }
            }
            return matches; 
        }
        // извлечь объекты из данных
        public DataObject[] DecodeString(
            TagScheme tagScheme, Authority outerAuthority, byte[] encoded)
        {
            // создать список объектов
            DataObject[] objs = new DataObject[headers.Length]; int offset = 0; 

            // для всех объектов
            for (int i = 0; i < headers.Length; offset += headers[i].Length, i++)
            {
                // проверить наличие объекта
                if (offset + headers[i].Length > encoded.Length) throw new IOException(); 

                // выделить память для закодированного представления
                byte[] content = new byte[headers[i].Length]; 

                // скопировать значение
                Array.Copy(encoded, offset, content, 0, headers[i].Length); 

                // раскодировать объект
                objs[i] = tagScheme.Decode(outerAuthority, headers[i].Tag, content); 
            }
            return objs; 
        }
    }
}
