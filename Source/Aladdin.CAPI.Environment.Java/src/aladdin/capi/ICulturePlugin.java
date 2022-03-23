package aladdin.capi;
import aladdin.capi.pbe.*;

///////////////////////////////////////////////////////////////////////////
// Расширение криптографических культур
///////////////////////////////////////////////////////////////////////////
public interface ICulturePlugin extends IParametersFactory, IPBECultureFactory
{
    // параметры шифрования по паролю
    public PBEParameters pbeParameters(); 
}

