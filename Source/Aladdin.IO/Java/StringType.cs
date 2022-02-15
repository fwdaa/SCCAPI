using System;
using System.IO;
using System.Text;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////    
    // Строковый тип Java
    ///////////////////////////////////////////////////////////////////////////    
    public class StringType : JavaType
    {
        // экземпляр типа
        public static readonly StringType Instance = new StringType(); 

        // имя типа 
        public override string Name { get { return "java.lang.String"; }}
        // декорированное имя типа
        public override string DecoratedName { get { return "Ljava.lang.String;"; }}

        // закодировать значение
        public override byte[] Encode(SerialStream stream, object value)
        {
            // проверить наличие объекта
            if (value == null) return new byte[] { 0x70 }; 

            // закодировать строку
            byte[] utf8 = Encoding.UTF8.GetBytes((string)value); 
            
            // добавить строку в список
            int length = utf8.Length; stream.Objects.Add(value);

            // проверить размер строки
            if (length <= UInt16.MaxValue)
            { 
                // выделить буфер требуемого размера
                byte[] encoded = new byte[3 + length]; encoded[0] = 0x74;

                // закодировать размер
                stream.EncodeShort((short)length, encoded, 1); 

                // скопировать закодированную строку
                Array.Copy(utf8, 0, encoded, 3, length); return encoded;
            }
            else { 
                // выделить буфер требуемого размера
                byte[] encoded = new byte[9 + length]; encoded[0] = 0x7C;

                // закодировать размер
                stream.EncodeLong(length, encoded, 1); 

                // скопировать закодированную строку
                Array.Copy(utf8, 0, encoded, 9, length); return encoded;
            }
        }
        // раскодировать значение
        public object Decode(SerialStream stream, 
            byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера 
            if (length < 1) throw new InvalidDataException(); size = 1; 
            
            // проверить наличие строки
            if (encoded[offset] == 0x70) return null; 
            
            // в зависимости от типа
            else if (encoded[offset] == 0x74)
            { 
                // проверить корректность размера
                if (length < 3) throw new InvalidDataException(); 

                // раскодировать размер имени
                size = 3 + stream.DecodeShort(encoded, offset + 1, 2); 

                // проверить корректность размера
                if (length < size) throw new InvalidDataException();

                // раскодировать строку
                string obj = Encoding.UTF8.GetString(encoded, offset + 3, size - 3); 

                // добавить строку в список
                stream.Objects.Add(obj); return obj; 
            }
            else if (encoded[offset] == 0x7C)
            {
                // проверить корректность размера
                if (length < 9) throw new InvalidDataException(); 

                // раскодировать размер имени
                size = 9 + (int)stream.DecodeLong(encoded, offset + 1, 8); 

                // проверить корректность размера
                if (length < size) throw new InvalidDataException();

                // раскодировать строку
                string obj = Encoding.UTF8.GetString(encoded, offset + 9, size - 9); 

                // добавить строку в список
                stream.Objects.Add(obj); return obj; 
            }
            // при ошибке выбросить исключение
            else throw new InvalidDataException(); 
        }
    }
}
