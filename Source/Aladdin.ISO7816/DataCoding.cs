using System;
using System.Collections.Generic;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Способ кодирования данных
    ///////////////////////////////////////////////////////////////////////////////
    public class DataCoding 
    {
        // схема кодирования и байт способа записи и дополнения
        private TagScheme scheme; private byte value; 
    
        // конструктор
        public DataCoding(TagScheme scheme) : this(scheme, 0x01) {}
    
        // конструктор
        public DataCoding(TagScheme scheme, byte value) 
        { 
            // сохранить переданные параметры
            this.scheme = scheme; this.value = value; 
        }
        // конструктор
        public DataCoding(DataCoding dataCoding, TagScheme scheme) 
        { 
            // сохранить переданные параметры
            this.scheme = scheme; this.value = dataCoding.value; 
        }
        // используемая схема кодирования
        public TagScheme TagScheme { get { return scheme; }}
    
        // способ записи
        public WriteType WriteEraseType { get  
        {
            switch ((value >> 5) & 0x3)
            {
            case 0: return WriteType.WriteErased; 
            case 2: return WriteType.WriteOr; 
            case 3: return WriteType.WriteAnd; 
            }
            return WriteType.Proprietary; 
        }}
        // размер адресуемых единиц в тетрадах
        public int QuartetUnitSize { get 
        {
            // вернуть адресуемых единиц в тетрадах
            return (1 << (value & 0x0F)); 
        }}
        // извлечь закодированные представления
        public ASN1.IEncodable[] Extract(byte[] content) 
        {
            // указать возможность дополнения байтами FF
            bool paddingFF = ((value & 0x10) == 0); int offset = 0; 
            
            // создать пустой список закодированных представлений
            List<ASN1.IEncodable> encodables = new List<ASN1.IEncodable>(); 

            // для всех байтов содержимого
            for (; offset < content.Length; offset++)
            {
                // проверить наличие заполнения
                if (paddingFF && content[offset] == 0xFF) continue; 

                // проверить отсутствие заполнения
                if (content[offset] != 0) break; 
            }
            // для всех внутренних объектов
            while (offset < content.Length)
            { 
                // раскодировать содержимое
                ASN1.IEncodable encodable = ASN1.Encodable.Decode(
                    content, offset, content.Length - offset
                ); 
                // добавить представление в список
                encodables.Add(encodable); offset += encodable.Encoded.Length; 
            
                // для всех байтов содержимого
                for (; offset < content.Length; offset++)
                {
                    // проверить наличие заполнения
                    if (paddingFF && content[offset] == 0xFF) continue; 

                    // проверить отсутствие заполнения
                    if (content[offset] != 0) break; 
                }
            }
            // вернуть раскодированные объекты
            return encodables.ToArray(); 
        }
        // закодировать объекты
        public byte[] Encode(params DataObject[] objects)
        {
            // закодировать объекты
            return DataObject.Encode(scheme, objects); 
        }
        // раскодировать объекты
        public DataObject[] Decode(byte[] content, bool interindustry)
        {
            // указать параметры
            Authority outerAuthority = (interindustry) ? Authority.ISO7816 : null; 
        
            // раскодировать объекты
            return Decode(outerAuthority, content); 
        }
        // раскодировать объекты
        public DataObject[] Decode(Authority outerAuthority, byte[] content) 
        {
            // извлечь закодированные представления
            ASN1.IEncodable[] encodables = Extract(content); 
        
            // создать список объектов
            DataObject[] objs = new DataObject[encodables.Length]; 
        
            // для всех закодированных представлений
            for (int i = 0; i < encodables.Length; i++)
            {
                // определить тип представления
                Tag tag = new Tag(encodables[i].Tag, encodables[i].PC); 
            
                // раскодировать объекты
                objs[i] = scheme.Decode(outerAuthority, tag, encodables[i].Content); 
            }
            return objs; 
        }
    }
}
