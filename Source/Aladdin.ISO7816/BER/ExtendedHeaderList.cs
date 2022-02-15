using System; 
using System.IO; 
using System.Collections.Generic; 

namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Расширенный список заголовков (0x4D)
    ///////////////////////////////////////////////////////////////////////////
    public class ExtendedHeaderList : DataObject
    {
        // список заголовков
        public readonly ExtendedHeader[] headers; 

        // конструктор закодирования 
        public ExtendedHeaderList(params ExtendedHeader[] headers) 
         
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.ExtendedHeaderList) { this.headers = headers; } 

        // конструктор раскодирования
        public ExtendedHeaderList(byte[] content) 
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.ExtendedHeaderList, content) 
        {
            // раскодировать заголовки
            headers = ExtendedHeader.Decode(content, 0, content.Length); 
        }
        // закодированное представление
        public override byte[] Content { get 
        {
            // закодировать заголовки
            return ExtendedHeader.Encode(headers); 
        }}
        // извлечь требуемые поля из объектов
        public ASN1.IEncodable[] Apply(ASN1.IEncodable[] encodables)
        {
            // создать список совпавших объектов
            List<ASN1.IEncodable> result = new List<ASN1.IEncodable>(); 
        
            // для всех заголовков
            for (int i = 0, index = 0; i < headers.Length; i++)
            {
                // для всех представлений
                for (int j = index; j < encodables.Length; j++)
                {
                    // извлечь тип объекта
                    Tag tag = new Tag(encodables[j].Tag, encodables[j].PC);
            
                    // проверить совпадение типа
                    if (headers[i].Header.Tag != tag) continue; index = j + 1;
                    
                    // извлечь требуемые поля из объекта
                    ASN1.IEncodable matched = headers[i].Apply(encodables[j]); 
                    
                    // добавить представление в список
                    if (matched != null) result.Add(matched); break;
                }
            }
            // вернуть совпавшие объекты
            return result.ToArray(); 
        }
        // извлечь объекты из данных
        public DataObject[] DecodeString(
            TagScheme tagScheme, Authority outerAuthority, byte[] encoded)
        {
            // создать список объектов
            List<DataObject> objs = new List<DataObject>(); int offset = 0; 
            
            // для всех внутренних объектов
            for (int i = 0; i < headers.Length; i++)
            {
                // извлечь закодированное представление
                ASN1.IEncodable encodable = headers[i].DecodeString(
                    tagScheme, encoded, ref offset
                ); 
                // проверить наличие представления
                if (encodable == null) continue;  

                // определить тип содержимого
                Tag tag = new Tag(encodable.Tag, encodable.PC); 

                // раскодировать объект
                objs.Add(tagScheme.Decode(outerAuthority, tag, encodable.Content)); 
            }
            return objs.ToArray(); 
        }
    }
}
