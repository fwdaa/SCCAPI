using System;
using System.IO;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////    
    // Тип boolean Java
    ///////////////////////////////////////////////////////////////////////////    
    public class BooleanType : JavaType
    {
        // экземпляр типа
        public static readonly BooleanType Instance = new BooleanType(); 

        // имя типа 
        public override string Name { get { return "boolean"; }}
        // декорированное имя типа
        public override string DecoratedName { get { return "Z"; }}

        // закодировать значение
        public override byte[] Encode(SerialStream stream, object value)
        {
            // закодировать значение
            return new byte[] { (bool)value ? (byte)1 : (byte)0 }; 
        }
        // раскодировать значение
        public object Decode(SerialStream stream, 
            byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера
            if (length < 1) throw new InvalidDataException(); 

            // раскодировать значение
            size = 1; return encoded[offset] != 0; 
        }
    }
}
