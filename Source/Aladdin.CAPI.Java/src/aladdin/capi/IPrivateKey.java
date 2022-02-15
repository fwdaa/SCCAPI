package aladdin.capi;
import aladdin.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма
///////////////////////////////////////////////////////////////////////////
public interface IPrivateKey extends IRefObject, java.security.PrivateKey
{
	Factory       factory   (); // фабрика алгоритмов
    SecurityStore scope     (); // область видимости
    Container     container (); // контейнер ключа
    KeyFactory    keyFactory(); // фабрика кодирования
    String        keyOID    (); // идентификатор ключа
	IParameters   parameters(); // параметры ключа
    
    // закодировать ключ
    PrivateKeyInfo encode(Attributes attributes) throws IOException;  
}
