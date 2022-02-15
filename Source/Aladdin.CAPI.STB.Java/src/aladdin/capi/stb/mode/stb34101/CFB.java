package aladdin.capi.stb.mode.stb34101;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////////
// Режим CFB
//////////////////////////////////////////////////////////////////////////////
public class CFB extends aladdin.capi.mode.CFB
{
    // конструктор
	public CFB(Cipher engine, CipherMode.CFB parameters) 
    { 
        // сохранить переданные параметры
        super(engine, parameters); 
    }
}
