using System; 
using System.IO; 
using System.Collections; 
using System.Collections.Generic; 

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////
    // Объект данных SIMPLE-TLV
    ///////////////////////////////////////////////////////////////////////
    public class SimpleTLV
    {
        // закодировать объекты
        public static byte[] Encode(SimpleTLV[] objects)
        {
            // выделить память для закодированных представлений
            byte[][] encodeds = new byte[objects.Length][];  

            // получить закодированные представления
            for (int i = 0; i < objects.Length; i++) encodeds[i] = objects[i].Encoded;

            // объединить закодированные представления
            return Arrays.Concat(encodeds); 
        }
        // раскодировать объекты
        public static SimpleTLV[] Decode(byte[] content)
        {
            // создать пустой список объектов
            List<SimpleTLV> objects = new List<SimpleTLV>(); 

            // для всех внутренних объектов
            for (int offset = 0; offset < content.Length; )
            { 
                // раскодировать содержимое
                SimpleTLV obj = new SimpleTLV(content, offset, content.Length - offset); 

                // перейти на следующий объект
                objects.Add(obj); offset += obj.Encoded.Length; 
            }
            // вернуть раскодированные объекты
            return objects.ToArray(); 
        }
        // тип и значение
        private int tag; private byte[] value; 

        // конструктор
        public SimpleTLV(int tag, byte[] value) 
        { 
            // проверить корректноть заголовка
            if (tag <= 0 || 0xFF <= tag) throw new ArgumentException(); 

            // проверить корректность размера
            if (value.Length > 0xFFFF) throw new ArgumentException();

            // сохранить переданные значения
            this.tag = tag; this.value = value; 
        }
        // раскодировать данные
        public SimpleTLV(byte[] encoded, int offset, int length)
        {
            // проверить корректность размера
            if (length < 2) throw new InvalidDataException(); 

            // проверить корректность данных
            if (encoded[offset] == 0x00 || encoded[offset] == 0xFF) 
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException();
            }
            // в зависимости от размера
            tag = encoded[offset]; if (encoded[offset + 1] != 0xFF)
            {
                // проверить размер данных
                if (length < 2 + encoded[offset + 1]) throw new InvalidDataException();

                // создать буфер для данных
                value = new byte[encoded[offset + 1]]; 

                // скопировать данные
                Array.Copy(encoded, 2 + offset, value, 0, value.Length); 
            }
            else { 
                // проверить корректность размера
                if (length < 4) throw new InvalidDataException();

                // раскодировать размер данных
                int cb = (encoded[offset + 2] << 8) | encoded[offset + 3]; 

                // проверить размер данных
                if (length < 4 + cb) throw new InvalidDataException();

                // скопировать данные
                value = new byte[cb]; Array.Copy(encoded, 4 + offset, value, 0, cb);
            }
        }
        // значение типа и данных
        public int Tag { get { return tag; }}

        // содержимое объекта
        public byte[] Value { get { return value; }}

        // получить закодированное представление
        public byte[] Encoded { get 
        { 
            // в зависимости от размера данных
            if (value.Length < 0xFF)
            {
                // выделить память для представления
                byte[] encoded = new byte[value.Length + 2]; 

                // указать заголовок и размер
                encoded[0] = (byte)tag; encoded[1] = (byte)value.Length; 

                // скопировать данные
                Array.Copy(value, 0, encoded, 2, value.Length); return encoded; 
            }
            else {
                // выделить память для представления
                byte[] encoded = new byte[value.Length + 4]; 

                // указать заголовок
                encoded[0] = (byte) tag; encoded[1] = 0xFF; 

                // закодировать размер
                encoded[2] = (byte) (value.Length >>   8); 
                encoded[3] = (byte) (value.Length & 0xFF); 

                // скопировать данные
                Array.Copy(value, 0, encoded, 4, value.Length); return encoded; 
            }
        }}
    }
}
