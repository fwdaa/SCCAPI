namespace Aladdin.IO.Java
{
    ///////////////////////////////////////////////////////////////////////////    
    // Тип char Java
    ///////////////////////////////////////////////////////////////////////////    
    public class CharType : JavaType
    {
        // экземпляр типа
        public static readonly CharType Instance = new CharType(); 

        // имя типа 
        public override string Name { get { return "char"; }}
        // декорированное имя типа
        public override string DecoratedName { get { return "C"; }}

        // закодировать значение
        public override byte[] Encode(SerialStream stream, object value)
        {
            // закодировать значение
            return stream.EncodeShort((short)(char)value); 
        }
        // раскодировать значение
        public object Decode(SerialStream stream, 
            byte[] encoded, int offset, int length, out int size)
        {
            // раскодировать значение
            return (char)stream.DecodeShort(encoded, offset, length, out size); 
        }
    }
}
