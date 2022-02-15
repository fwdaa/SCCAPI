namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////    
    // Тип int Java
    ///////////////////////////////////////////////////////////////////////////    
    public class IntegerType : JavaType
    {
        // экземпляр типа
        public static readonly IntegerType Instance = new IntegerType(); 

        // имя типа 
        public override string Name { get { return "int"; }}
        // декорированное имя типа
        public override string DecoratedName { get { return "I"; }}

        // закодировать значение
        public override byte[] Encode(SerialStream stream, object value)
        {
            // закодировать значение
            return stream.EncodeInteger((int)value); 
        }
        // раскодировать значение
        public object Decode(SerialStream stream,
            byte[] encoded, int offset, int length, out int size)
        {
            // раскодировать значение
            return stream.DecodeInteger(encoded, offset, length, out size); 
        }
    }
}
