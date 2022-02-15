using System; 
using System.IO; 

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////
    // Ответ APDU
    ///////////////////////////////////////////////////////////////////////////
    public class Response
    {
        // код завершения
        public readonly byte[] Data; public readonly ushort SW;

        // конструктор
        public Response(ushort sw) : this(new byte[0], sw) {}

        // конструктор
        public Response(byte[] data, ushort sw)
        {
            // проверить корректность данных
            if (sw < 0x6100 || 0xA000 <= sw) throw new ArgumentException(); 

            // сохранить переданные параметры
            Data = data; SW = sw; encoded = new byte[data.Length + 2];

            // скопировать данные
            Array.Copy(data, 0, encoded, 0, data.Length); 

            // закодировать код завершения
            encoded[encoded.Length - 2] = (byte)(sw >>   8); 
            encoded[encoded.Length - 1] = (byte)(sw & 0xFF); 
        }
        // раскодировать ответ
        public Response(byte[] encoded)
        {
            // проверить корректность размера
            if (encoded.Length < 2) throw new InvalidDataException(); 

            // выделить память для данных
            Data = new byte[encoded.Length - 2]; this.encoded = encoded; 

            // скопировать данные
            Array.Copy(encoded, 0, Data, 0, Data.Length); 

            // раскодировать код завершения
            SW = (ushort)((encoded[encoded.Length - 2] << 8) | encoded[encoded.Length - 1]); 

            // проверить корректность данных
            if (SW < 0x6100 || 0xA000 <= SW) throw new InvalidDataException(); 
        }
        // признак отсутствия ошибок
        public static bool Normal(Response response) 
        { 
            // признак отсутствия ошибок
            return ((response.SW & 0xF000) == 0x9000 || (response.SW & 0xFF00) == 0x6100); 
        }
        // признак предупреждения
        public static bool Warning(Response response) 
        { 
            // признак предупреждения
            return (0x6200 <= response.SW && response.SW < 0x6400); 
        }
        // признак ошибки
        public static bool Error(Response response) 
        { 
            // проверить корректность данных
            if (response.SW < 0x6100 || 0xA000 <= response.SW) return true; 

            // признак ошибки
            return response.SW >= 0x6400; 
        }
        // закодированное представление
        public byte[] Encoded { get { return encoded; }} private byte[] encoded; 
    }
}
