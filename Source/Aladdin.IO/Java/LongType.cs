namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////    
    // Тип long Java
    ///////////////////////////////////////////////////////////////////////////    
    public class LongType : JavaType
    {
        // экземпляр типа
        public static readonly LongType Instance = new LongType(); 

        // имя типа 
        public override string Name { get { return "long"; }}
        // декорированное имя типа
        public override string DecoratedName { get { return "J"; }}

        // закодировать значение
        public override byte[] Encode(SerialStream stream, object value)
        {
            // закодировать значение
            return stream.EncodeLong((long)value); 
        }
        // раскодировать значение
        public object Decode(SerialStream stream, 
            byte[] encoded, int offset, int length, out int size)
        {
            // раскодировать значение
            return stream.DecodeLong(encoded, offset, length, out size); 
        }
    }
}
