package aladdin.capi;
import aladdin.*; 
import aladdin.capi.pbe.*;

///////////////////////////////////////////////////////////////////////////
// Расширение криптографических культур
///////////////////////////////////////////////////////////////////////////
public interface ICulturePlugin extends IRefObject, IParametersFactory, IPBECultureFactory
{
    // параметры шифрования по паролю
    public PBEParameters pbeParameters(); 
}

