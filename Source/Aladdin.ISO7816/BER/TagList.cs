using System;
using System.Collections.Generic;
using System.IO;

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Список тэгов (0x5С)
    ///////////////////////////////////////////////////////////////////////////
    public class TagList : DataObject
    {
        // список тэгов
        public readonly Tag[] tags; 

        // конструктор закодирования 
        public TagList(params Tag[] tags) 
         
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.TagList) { this.tags = tags; }
         
        // конструктор раскодирования
        public TagList(byte[] content) 
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.TagList, content) 
        {
            // создать пустой список тэгов
            List<Tag> tags = new List<Tag>(); 
        
            // для всех внутренних объектов
            for (int offset = 0; offset < content.Length; )
            { 
                // раскодировать тэг
                Tag tag = Tag.Decode(
                    content, offset, content.Length - offset
                ); 
                // перейти на следующий объект
                tags.Add(tag); offset += tag.Encoded.Length;
            }
            // сохранить раскодированные объекты
            this.tags = tags.ToArray(); 
        }
        // закодированное представление
        public override byte[] Content { get 
        {
            // выделить память для закодированных представлений
            byte[][] encodeds = new byte[tags.Length][];  

            // для всех тэгов
            for (int i = 0; i < tags.Length; i++) 
            {
                // получить закодированное представление
                encodeds[i] = tags[i].Encoded;
            }
            // объединить закодированные представления
            return Arrays.Concat(encodeds); 
        }}
        // извлечь требуемые поля из объектов
        public ASN1.IEncodable[] Apply(ASN1.IEncodable[] encodables)
        {
            // проверить наличие тэгов
            if (tags.Length == 0) return encodables; 

            // создать список совпавших объектов
            ASN1.IEncodable[] matches = new ASN1.IEncodable[tags.Length]; 
        
            // для всех заголовков
            for (int i = 0, index = 0; i < tags.Length; i++)
            {
                // для всех представлений
                for (int j = index; j < encodables.Length; j++)
                {
                    // извлечь тип объекта
                    Tag tag = new Tag(encodables[j].Tag, encodables[j].PC);
            
                    // проверить совпадение типа
                    if (tags[i] != tag) continue; index = j + 1; 
                    
                    // добавить представление в список
                    matches[i] = encodables[j]; break;
                }
            }
            return matches; 
        }
    }
}
