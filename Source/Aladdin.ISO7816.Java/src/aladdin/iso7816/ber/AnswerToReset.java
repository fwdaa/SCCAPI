package aladdin.iso7816.ber;
import aladdin.iso7816.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Ответ-на-восстановление (0x5F 0x51)
///////////////////////////////////////////////////////////////////////////
public class AnswerToReset extends DataObject
{
    // ответ-на-восстановление
    public final ATR value; 

    // конструктор закодирования
    public AnswerToReset(ATR value) 
    {     
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.ANSWER_TO_RESET, value.encoded); this.value = value;
    }
    // конструктор раскодирования
    public AnswerToReset(byte[] content) throws IOException
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.ANSWER_TO_RESET, content); value = new ATR(content);
    }
}
