using System;
using System.IO;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////    
    // Тип Date Java
    ///////////////////////////////////////////////////////////////////////////    
    public class DateType : ObjectType
    {
        // экземпляр типа
        public static readonly DateType Instance = new DateType(); 

        // указать наличие собственного способа записи
        public const byte Flags = Java.ClassDesc.SC_SERIALIZABLE | Java.ClassDesc.SC_WRITE_METHOD; 

        // конструктор
        public DateType() : base(new ClassDesc(
            "java.util.Date", 7523967970034938905L, Flags, null, new FieldDesc[0])) {}

        // закодировать значение
        public override byte[] EncodeValue(SerialStream stream, object value)
        {
            // выполнить преобразование типа
            DateTime dateTime = ((DateTime)value).ToUniversalTime(); 

            // вычислить разницу во времени
            TimeSpan delta = dateTime - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); 

            // выделить буфер требуемого размера
            byte[] encoded = new byte[11]; encoded[0] = 0x77; encoded[10] = 0x78; 

            // закодировать значение
            encoded[1] = 0x08; stream.EncodeLong((long)delta.TotalMilliseconds, encoded, 2); return encoded; 
        }
        // раскодировать значение
        public override object DecodeValue(
            SerialStream stream, byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера
            if (length < 11 || encoded[offset] != 0x77 || encoded[offset + 10] != 0x78) 
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException(); 
            }
            // проверить корректность размера
            if (encoded[offset + 1] != 0x08) throw new InvalidDataException(); size = 11;

            // скопировать данные
            byte[] buffer = new byte[8]; Array.Copy(encoded, offset + 2, buffer, 0, buffer.Length); 

            // раскодировать число миллисекунд
            Array.Reverse(buffer); long milliseconds = BitConverter.ToInt64(buffer, 0); 

            // преобразовать число миллисекунд
            TimeSpan delta = TimeSpan.FromMilliseconds(milliseconds); 

            // вернуть раскодированное время
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc) + delta; 
        }
    }
}
