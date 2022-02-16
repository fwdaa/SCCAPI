package aladdin.capi.stb.stb11762;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public interface IBDHPublicKey extends aladdin.capi.IPublicKey 
{
	BigInteger bdhY(); // параметр Y
}