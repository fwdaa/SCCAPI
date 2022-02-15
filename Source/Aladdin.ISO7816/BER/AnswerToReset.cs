namespace Aladdin.ISO7816.BER
{
    ///////////////////////////////////////////////////////////////////////////
    // Ответ-на-восстановление (0x5F 0x51)
    ///////////////////////////////////////////////////////////////////////////
    public class AnswerToReset : DataObject
    {
        // конструктор закодирования
        public AnswerToReset(ATR value) 
    
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.AnswerToReset, value.Encoded) 
    
            // сохранить переданные параметры
            { Value = value; } public readonly ATR Value;
    
        // конструктор раскодирования
        public AnswerToReset(byte[] content)
    
            // сохранить переданные параметры
            : base(Authority.ISO7816, ISO7816.Tag.AnswerToReset, content)  
        {
            // раскодировать ATR
            Value = new ATR(content); 
        }
    }
}
