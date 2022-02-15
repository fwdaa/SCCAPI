package aladdin.capi.gost.gostr3410;
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма ГОСТ Р 34.10-1994,2001,2012
///////////////////////////////////////////////////////////////////////////
public interface IECPrivateKey extends aladdin.capi.IPrivateKey 
{
	BigInteger getS() throws IOException;	// координата X точки 
}
