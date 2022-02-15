using System;
using System.IO;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////    
    // Тип byte Java
    ///////////////////////////////////////////////////////////////////////////    
    public class ByteType : JavaType
    {
        // экземпляр типа
        public static readonly ByteType Instance = new ByteType(); 

        // имя типа 
        public override string Name { get { return "byte"; }}
        // декорированное имя типа
        public override string DecoratedName { get { return "B"; }}

        // закодировать значение
        public override byte[] Encode(SerialStream stream, object value)
        {
            // закодировать значение
            return new byte[] { (byte)value }; 
        }
        // раскодировать значение
        public object Decode(SerialStream stream, 
            byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера
            if (length < 1) throw new InvalidDataException(); 

            // раскодировать значение
            size = 1; return encoded[offset]; 
        }
    }
}
