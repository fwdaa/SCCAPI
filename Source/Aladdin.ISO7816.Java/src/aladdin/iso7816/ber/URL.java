package aladdin.iso7816.ber;
import aladdin.iso7816.*; 

///////////////////////////////////////////////////////////////////////////
// Унифицированный указатель ресурса (0x5F 0x50)
///////////////////////////////////////////////////////////////////////////
public class URL extends DataObject
{
    // конструктор
    public URL(byte[] content) 
    {    
        // сохранить переданные параметры
        super(Authority.ISO7816, Tag.UNIFORM_RESOURCE_LOCATOR, content); 
    } 
}
