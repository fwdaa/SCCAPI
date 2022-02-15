using System;

namespace Aladdin
{
    ///////////////////////////////////////////////////////////////////////////
    // Кодирование Base-64
    ///////////////////////////////////////////////////////////////////////////
    public static class Base64
    {
        // получить способ закодирования данных
        public static Encoder GetEncoder(Base64FormattingOptions options) 
        { 
            // получить способ закодирования данных
            return new Encoder(options); 
        }
        // способ закодирования данных
        public static Encoder GetEncoder()
        { 
            // способ закодирования данных
            return GetEncoder(Base64FormattingOptions.None); 
        }
        // способ раскодирования данных
        public static Decoder GetDecoder() { return new Decoder(); }

        ///////////////////////////////////////////////////////////////////////
        // Закодирование данных
        ///////////////////////////////////////////////////////////////////////
        public class Encoder
        {
            // способ кодирования данных
            private Base64FormattingOptions options; 

            // конструктор
            internal Encoder(Base64FormattingOptions options) 
            {
                // сохранить переданные параметры
                this.options = options; 
            }
            // закодировать данные
            public string EncodeToString(byte[] buffer)
            {
                // закодировать данные
                return EncodeToString(buffer, 0, buffer.Length); 
            }
            // закодировать данные
            public string EncodeToString(byte[] buffer, int offset, int length)
            {
                // закодировать данные
                return Convert.ToBase64String(buffer, offset, length, options); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Раскодирование данных
        ///////////////////////////////////////////////////////////////////////
        public class Decoder
        {
            // конструктор
            internal Decoder() {}

            // раскодировать данные
            public byte[] Decode(string encoded)
            {
                // раскодировать данные
                return Convert.FromBase64String(encoded); 
            }
        }
    }
}
