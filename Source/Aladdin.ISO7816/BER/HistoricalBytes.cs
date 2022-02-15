namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Байты предыстории (0x5F 0x52)
    ///////////////////////////////////////////////////////////////////////////
    public class HistoricalBytes : DataObject
    {
        // байты предыстории
        public readonly ISO7816.HistoricalBytes Value; 

        // конструктор закодирования
        public HistoricalBytes(ISO7816.HistoricalBytes value) 
             
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.HistoricalBytes, value.Encoded) 
        {
            // сохранить переданные параметры
            Value = value;
        }
        // конструктор раскодирования
        public HistoricalBytes(byte[] content)
        
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.HistoricalBytes, content) 
        {
            // раскодировать байты предыстории
            Value = new ISO7816.HistoricalBytes(content, 0, content.Length);
        }
    }
}
