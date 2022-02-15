using System; 
using System.IO; 
using System.Collections; 
using System.Collections.Generic; 

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////
    // Объект данных COMPACT-TLV
    ///////////////////////////////////////////////////////////////////////
    public class CompactTLV
    {
        // закодировать объекты
        public static byte[] Encode(CompactTLV[] objects)
        {
            // выделить память для закодированных представлений
            byte[][] encodeds = new byte[objects.Length][];  

            // получить закодированные представления
            for (int i = 0; i < objects.Length; i++) encodeds[i] = objects[i].Encoded;

            // объединить закодированные представления
            return Arrays.Concat(encodeds); 
        }
        // раскодировать объекты
        public static CompactTLV[] Decode(byte[] content)
        {
            // создать пустой список объектов
            List<CompactTLV> objects = new List<CompactTLV>(); 

            // для всех внутренних объектов
            for (int offset = 0; offset < content.Length; )
            { 
                // раскодировать содержимое
                CompactTLV obj = new CompactTLV(content, offset, content.Length - offset); 

                // перейти на следующий объект
                objects.Add(obj); offset += obj.Encoded.Length; 
            }
            // вернуть раскодированные объекты
            return objects.ToArray(); 
        }
        // тип и значение
        private int tag; private byte[] value; 

        // конструктор
        public CompactTLV(Tag tag, byte[] content) 
        { 
            // проверить корректность заголовка
            if (tag.AsnTag.Class != ASN1.TagClass.Application) throw new ArgumentException();

            // проверить корректность заголовка и размера
            if (tag.AsnTag.Value > 0xF) throw new ArgumentException();

            // проверить корректность размера
            if (content.Length > 0xF) throw new ArgumentOutOfRangeException();

            // сохранить переданные значения
            this.tag = tag.AsnTag.Value; this.value = content; 
        }
        // раскодировать данные
        public CompactTLV(byte[] encoded, int offset, int length)
        {
            // проверить корректность размера
            if (length < 1) throw new InvalidDataException(); 

            // извлечь тип и размер данных 
            tag = encoded[offset] >> 4; int cb = encoded[offset] & 0x0F;
            
            // проверить размер данных
            if (length < 1 + cb) throw new InvalidDataException(); 

            // скопировать данные
            value = new byte[cb]; Array.Copy(encoded, offset + 1, value, 0, cb); 
        }
        // значение типа
        public Tag Tag { get { return Tag.Application(tag, ASN1.PC.Primitive); }}

        // содержимое объекта
        public byte[] Value { get { return value; }}

        // получить закодированное представление
        public byte[] Encoded { get 
        { 
            // выделить память для представления
            byte[] encoded = new byte[1 + value.Length]; 

            // указать заголовок и размер
            encoded[0] = (byte) ((tag << 4) | value.Length); 

            // скопировать данные
            Array.Copy(value, 0, encoded, 1, value.Length); return encoded;
        }}
        // выполнить преобразование типа
        public DataObject ToObject() { return new DataObject(this); }
    }
}

