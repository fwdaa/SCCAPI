package aladdin.capi.retro.java.security.interfaces;
import aladdin.capi.retro.java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Ключ алгоритма на эллиптических кривых
///////////////////////////////////////////////////////////////////////////////
public interface ECKey 
{
    // параметры алгоритма на эллиптических кривых
    ECParameterSpec getParams();
}
