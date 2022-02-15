package aladdin.iso7816.ber;
import aladdin.iso7816.*; 

///////////////////////////////////////////////////////////////////////////
// Метка приложения (0x50)
///////////////////////////////////////////////////////////////////////////
public class ApplicationLabel extends DataObject
{
    // конструктор
    public ApplicationLabel(byte[] content) 
    {        
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.APPLICATION_LABEL, content); 
    }
}
