using System;
using System.IO;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////
    // Описание поля класса Java
    ///////////////////////////////////////////////////////////////////////////
    public class FieldDesc
    {
        // раскодировать поле
        public static FieldDesc Decode(SerialStream stream, 
            byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера
            if (length < 1) throw new InvalidDataException();

            // извлечь первый символ
            char ch = (char)encoded[offset]; string type = null; 

            // перейти на следующее поле
            int next = 1; size = next; offset += next; length -= next; 

            // раскодировать имя поля
            string name = stream.DecodeName(encoded, offset, length, out next); 

            // перейти на следующее поле
            size += next; offset += next; length -= next; 

            // обработать примитивные типы
            if (ch != '[' && ch != 'L') type = new String(ch, 1); 
            else { 
                // раскодировать имя типа
                type = stream.DecodeString(encoded, offset, length, out next); 

                // перейти на следующее поле
                size += next; offset += next; length -= next; 
            }
            // вернуть описание поля с объектом
            return new FieldDesc(name, JavaType.UndecorateType(type)); 
        }
        // имя поля и имя его типа
        public readonly string Name; public readonly string Type; 

        // конструктор
        public FieldDesc(string name, string type) { Name = name; Type = type; }

        // закодировать поле
        public byte[] Encode(SerialStream stream) 
        { 
            // закодировать имя
            byte[] encodedName = stream.EncodeName(Name); 

            // выделить буфер требуемого размера
            byte[] encoded = new byte[1 + encodedName.Length]; 

            // выполнить декорирование имени
            string type = JavaType.DecorateType(Type); encoded[0] = (byte)type[0]; 

            // скопировать имя поля
            Array.Copy(encodedName, 0, encoded, 1, encodedName.Length); 

            // проверить необходимость дальнейших действий
            if (type[0] != '[' && type[0] != 'L') return encoded; int offset = encoded.Length;

            // закодировать декорированный тип
            byte[] encodedType = stream.EncodeString(type); 

            // выделить буфер требуемого размера
            Array.Resize(ref encoded, offset + encodedType.Length); 

            // скопировать имя типа
            Array.Copy(encodedType, 0, encoded, offset, encodedType.Length); return encoded;
        } 
    }
}
