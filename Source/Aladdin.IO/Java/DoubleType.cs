using System;
using System.IO;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////    
    // Тип double Java
    ///////////////////////////////////////////////////////////////////////////    
    public class DoubleType : JavaType
    {
        // экземпляр типа
        public static readonly DoubleType Instance = new DoubleType(); 

        // имя типа 
        public override string Name { get { return "double"; }}
        // декорированное имя типа
        public override string DecoratedName { get { return "D"; }}

        // закодировать значение
        public override byte[] Encode(SerialStream stream, object value)
        {
            // закодировать значение
            byte[] encoded = BitConverter.GetBytes((double)value);

            // изменить порядок следования байтов
            Array.Reverse(encoded); return encoded; 
        }
        // раскодировать значение
        public object Decode(SerialStream stream, 
            byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера
            if (length < 8) throw new InvalidDataException(); 

            // скопировать данные
            byte[] buffer = new byte[size = 8]; Array.Copy(encoded, offset, buffer, 0, size); 

            // раскодировать значение
            Array.Reverse(buffer); return BitConverter.ToDouble(buffer, 0); 
        }
    }
}
