package aladdin.capi.stb.stb11762;
import java.math.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры алгоритма выработки общего ключа СТБ 1176.2
///////////////////////////////////////////////////////////////////////////
public interface IBDHParameters extends aladdin.capi.IParameters
{
	int			bdhL(); // параметр L
	int			bdhR(); // параметр R
	BigInteger	bdhP(); // параметр P
	BigInteger	bdhG(); // параметр G
	int			bdhN(); // параметр R
    byte[]      bdhZ(); // параметры генерации
}
