package aladdin.capi.gost.gostr3410;
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма ГОСТ Р 34.10-1994
///////////////////////////////////////////////////////////////////////////
public interface IDHPrivateKey extends aladdin.capi.IPrivateKey 
{
	BigInteger getX() throws IOException;	// параметр X
}
