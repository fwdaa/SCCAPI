package aladdin.capi.ansi.kea;
import java.math.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма KEA
///////////////////////////////////////////////////////////////////////////
public interface IPrivateKey extends aladdin.capi.IPrivateKey
{
	BigInteger getX() throws IOException; // параметр X
}
