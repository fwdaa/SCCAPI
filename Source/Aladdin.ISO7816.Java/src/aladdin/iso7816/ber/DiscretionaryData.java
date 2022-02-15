package aladdin.iso7816.ber;
import aladdin.iso7816.*; 

///////////////////////////////////////////////////////////////////////////
// Произвольные данные (0x53)
///////////////////////////////////////////////////////////////////////////
public class DiscretionaryData extends DataObject
{
    // конструктор
    public DiscretionaryData(byte[] content) 
    {
        // сохранить переданные параметры
        this(Tag.DISCRETIONARY_DATA, content); 
    }
    // конструктор
    public DiscretionaryData(Tag tag, byte[] content) 
    {
        // сохранить переданные параметры
        super(Authority.ISO7816, tag, content); 
    }
}
