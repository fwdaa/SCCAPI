package aladdin.iso7816.ber;
import aladdin.iso7816.*; 

///////////////////////////////////////////////////////////////////////////
// Данные, предваряющие эмиссию карты (0x46)
///////////////////////////////////////////////////////////////////////////
public class PreIssuingData extends DataObject
{
    // конструктор
    public PreIssuingData(byte[] content) 
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.PRE_ISSUING_DATA, content); 
    }
}
