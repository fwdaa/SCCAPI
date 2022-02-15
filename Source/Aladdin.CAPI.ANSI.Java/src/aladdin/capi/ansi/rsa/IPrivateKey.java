package aladdin.capi.ansi.rsa;
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма RSA
///////////////////////////////////////////////////////////////////////////
public interface IPrivateKey extends aladdin.capi.IPrivateKey, java.security.interfaces.RSAKey
{
	BigInteger getPublicExponent ();                        // параметр E
	BigInteger getPrivateExponent() throws IOException;		// параметр D
	BigInteger getPrimeP		 () throws IOException;		// параметр P
	BigInteger getPrimeQ		 () throws IOException;		// параметр Q
	BigInteger getPrimeExponentP () throws IOException;		// параметр D (mod P-1)
	BigInteger getPrimeExponentQ () throws IOException;		// параметр D (mod Q-1)
	BigInteger getCrtCoefficient () throws IOException;		// параметр Q^{-1}(mod P)
}										 
