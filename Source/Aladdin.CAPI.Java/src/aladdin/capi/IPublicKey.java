package aladdin.capi;
import aladdin.asn1.iso.pkix.*; 

///////////////////////////////////////////////////////////////////////////
// Открытый ключ алгоритма
///////////////////////////////////////////////////////////////////////////
public interface IPublicKey extends java.security.PublicKey
{
    // идентификатор и параметры ключа
    String keyOID(); IParameters parameters();
    
    // фабрика кодирования и закодированное представление
	KeyFactory keyFactory(); SubjectPublicKeyInfo encoded(); 
}
