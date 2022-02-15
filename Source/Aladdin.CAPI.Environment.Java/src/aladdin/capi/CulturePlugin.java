package aladdin.capi;
import aladdin.*; 
import aladdin.capi.pbe.*; 

///////////////////////////////////////////////////////////////////////////
// Расширение криптографических культур
///////////////////////////////////////////////////////////////////////////
public abstract class CulturePlugin extends RefObject implements IParametersFactory, IPBECultureFactory
{
    // конструктор
    public CulturePlugin(PBEParameters pbeParameters)
        
        // сохранить переданные параметры
        { this.pbeParameters = pbeParameters; } private final PBEParameters pbeParameters;

    // параметры шифрования по паролю
    public final PBEParameters pbeParameters() { return pbeParameters; } 

    // параметры ключа
    @Override public abstract IParameters getParameters(IRand rand, String keyOID, KeyUsage keyUsage); 

    // криптографическая культура для PKCS12
    public abstract PBECulture getCulture(Object window, String keyOID);
}
