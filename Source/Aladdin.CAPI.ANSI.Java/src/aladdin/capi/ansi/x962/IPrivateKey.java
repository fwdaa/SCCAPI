package aladdin.capi.ansi.x962;
import java.math.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма 
///////////////////////////////////////////////////////////////////////////
public interface IPrivateKey extends aladdin.capi.IPrivateKey
{
	BigInteger getS() throws IOException; // секретное значение
}
