package aladdin.capi.stb.mode.stb34101;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////////
// Режим CBC
//////////////////////////////////////////////////////////////////////////////
public class CBC extends aladdin.capi.mode.CBC
{
    // конструктор
	public CBC(Cipher engine, CipherMode.CBC parameters) 
    { 
        // сохранить переданные параметры
        super(engine, parameters, PaddingMode.CTS); 
    }
}
