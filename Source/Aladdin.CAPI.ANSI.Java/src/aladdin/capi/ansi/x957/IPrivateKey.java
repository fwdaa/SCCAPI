package aladdin.capi.ansi.x957;
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма DSA
///////////////////////////////////////////////////////////////////////////
public interface IPrivateKey extends aladdin.capi.IPrivateKey
{
	BigInteger getX() throws IOException; 
}