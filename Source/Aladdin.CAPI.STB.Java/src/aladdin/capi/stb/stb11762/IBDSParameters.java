package aladdin.capi.stb.stb11762;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры алгоритма выработки/проверки подписи СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public interface IBDSParameters extends aladdin.capi.IParameters, 
    java.security.interfaces.DSAParams
{
	int			bdsL(); // параметр L
	int			bdsR(); // параметр R
	BigInteger	bdsP(); // параметр P
	BigInteger	bdsQ(); // параметр Q
	BigInteger	bdsA(); // параметр A
	byte[] 		bdsH(); // стартовое хэш-значение
    byte[]      bdsZ(); // параметры генерации
}
