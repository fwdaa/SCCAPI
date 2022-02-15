using System;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Открытый ключ алгоритма
	///////////////////////////////////////////////////////////////////////////
	public interface IPublicKey
	{
        // идентификатор и параметры ключа
		string KeyOID { get; } IParameters Parameters { get; } 

        // фабрика кодирования
	    KeyFactory KeyFactory { get; }

        // закодированное представление
        ASN1.ISO.PKIX.SubjectPublicKeyInfo Encoded { get; } 

        // преобразовать тип ключа
        System.Security.Cryptography.X509Certificates.PublicKey Convert(); 
	}
}
