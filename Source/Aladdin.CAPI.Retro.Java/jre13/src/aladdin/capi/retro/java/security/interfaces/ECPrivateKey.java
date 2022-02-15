package aladdin.capi.retro.java.security.interfaces;
import java.security.*;
import java.math.*;

///////////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма на эллиптических кривых
///////////////////////////////////////////////////////////////////////////////
public interface ECPrivateKey extends PrivateKey, ECKey 
{
    // значение личного ключа
    BigInteger getS();
}
