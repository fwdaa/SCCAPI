namespace Aladdin.CAPI.STB.Mode.STB34101
{
    ///////////////////////////////////////////////////////////////////////////////
    // Режим ECB
    //////////////////////////////////////////////////////////////////////////////
    public class CBC : CAPI.Mode.CBC
    {
        // конструктор
	    public CBC(CAPI.Cipher engine, CipherMode.CBC parameters) 
            
            // сохранить переданные параметры
            : base(engine, parameters, PaddingMode.CTS) {}
    }
}
