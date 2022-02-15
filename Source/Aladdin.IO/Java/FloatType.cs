using System; 
using System.IO;

namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////    
    // Тип float Java
    ///////////////////////////////////////////////////////////////////////////    
    public class FloatType : JavaType
    {
        // экземпляр типа
        public static readonly FloatType Instance = new FloatType(); 

        // имя типа 
        public override string Name { get { return "float"; }}
        // декорированное имя типа
        public override string DecoratedName { get { return "F"; }}

        // закодировать значение
        public override byte[] Encode(SerialStream stream, object value)
        {
            // закодировать значение
            byte[] encoded = BitConverter.GetBytes((float)value);

            // изменить порядок следования байтов
            Array.Reverse(encoded); return encoded; 
        }
        // раскодировать значение
        public object Decode(SerialStream stream, 
            byte[] encoded, int offset, int length, out int size)
        {
            // проверить корректность размера
            if (length < 4) throw new InvalidDataException(); 

            // скопировать данные
            byte[] buffer = new byte[size = 4]; Array.Copy(encoded, offset, buffer, 0, size); 

            // раскодировать значение
            Array.Reverse(buffer); return BitConverter.ToSingle(buffer, 0); 
        }
    }
}
