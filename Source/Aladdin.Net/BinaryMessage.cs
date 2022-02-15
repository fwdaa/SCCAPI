namespace Aladdin.Net
{
    ///////////////////////////////////////////////////////////////////////////
    // Сообщение с бинарным содержимым
    ///////////////////////////////////////////////////////////////////////////
    public class BinaryMessage<T> : Message
    {
        // тип сообщения и содержимое сообщения
        private T type; private byte[] body; 

        // конструктор
        public BinaryMessage(T type, byte[] body) 
        { 
            // сохранить переданные параметры
            this.type = type; this.body = body; 
        }
        // тип сообщения
        public override object Type { get { return type; }}

        // содержимое сообщения
        public byte[] Body { get { return body; }}
    }
}
