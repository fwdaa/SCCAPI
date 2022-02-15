package aladdin.capi.stb.stb11762;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public interface IBDSPublicKey extends aladdin.capi.IPublicKey, 
    java.security.interfaces.DSAPublicKey
{
	BigInteger bdsY(); 	// параметр Y
}
