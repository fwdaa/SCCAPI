package aladdin.capi.retro.java.security.interfaces;
import aladdin.capi.retro.java.security.spec.*;
import java.security.*;

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма на эллиптических кривых
///////////////////////////////////////////////////////////////////////////////
public interface ECPublicKey extends PublicKey, ECKey 
{
    // значение открытого ключа
    ECPoint getW();
}
