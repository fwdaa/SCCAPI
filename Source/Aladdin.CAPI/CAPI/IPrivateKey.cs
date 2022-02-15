using System;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ алгоритма
	///////////////////////////////////////////////////////////////////////////
	public interface IPrivateKey : IRefObject
	{
        Factory       Factory    { get; } // фабрика алгоритмов
		SecurityStore Scope      { get; } // область видимости
        Container     Container  { get; } // контейнер ключа
        KeyFactory    KeyFactory { get; } // фабрика кодирования
        String        KeyOID     { get; } // идентификатор ключа
        IParameters   Parameters { get; } // параметры ключа 

        // закодировать ключ
        ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo Encode(ASN1.ISO.Attributes attributes); 
	}
}
