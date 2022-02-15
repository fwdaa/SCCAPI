namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////    
    // Тип short Java
    ///////////////////////////////////////////////////////////////////////////    
    public class ShortType : JavaType
    {
        // экземпляр типа
        public static readonly ShortType Instance = new ShortType(); 

        // имя типа 
        public override string Name { get { return "short"; }}
        // декорированное имя типа
        public override string DecoratedName { get { return "S"; }}

        // закодировать значение
        public override byte[] Encode(SerialStream stream, object value)
        {
            // закодировать значение
            return stream.EncodeShort((short)value); 
        }
        // раскодировать значение
        public object Decode(SerialStream stream, 
            byte[] encoded, int offset, int length, out int size)
        {
            // раскодировать значение
            return stream.DecodeShort(encoded, offset, length, out size); 
        }
    }
}
