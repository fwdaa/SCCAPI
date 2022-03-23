using System;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Национальные особенности
	///////////////////////////////////////////////////////////////////////////
	public abstract class Culture
	{
		// параметры алгоритмов
        public virtual ASN1.ISO.AlgorithmIdentifier HashAlgorithm               (IRand rand) { return null; }
        public virtual ASN1.ISO.AlgorithmIdentifier HMacAlgorithm               (IRand rand) { return null; }
		public virtual ASN1.ISO.AlgorithmIdentifier CipherAlgorithm             (IRand rand) { return null; }
		public virtual ASN1.ISO.AlgorithmIdentifier KeyWrapAlgorithm            (IRand rand) { return null; }
		public virtual ASN1.ISO.AlgorithmIdentifier CiphermentAlgorithm         (IRand rand) { return null; }
	    public virtual ASN1.ISO.AlgorithmIdentifier SignHashAlgorithm           (IRand rand) { return null; }
	    public virtual ASN1.ISO.AlgorithmIdentifier SignDataAlgorithm           (IRand rand) { return null; }
		public virtual ASN1.ISO.AlgorithmIdentifier TransportKeyAlgorithm       (IRand rand) { return null; }
		public virtual ASN1.ISO.AlgorithmIdentifier TransportAgreementAlgorithm (IRand rand) { return null; }

	    ///////////////////////////////////////////////////////////////////////
	    // Параметры шифрования на открытом ключе (KeyX)
	    ///////////////////////////////////////////////////////////////////////
        public ASN1.ISO.AlgorithmIdentifier KeyxParameters(
            Factory factory, SecurityStore scope, IRand rand, KeyUsage keyUsage)
        {
            // при допустимости транспорта ключа
            if ((keyUsage & KeyUsage.KeyEncipherment) != KeyUsage.None)
            {
                // создать список параметров 
                ASN1.ISO.AlgorithmIdentifier keyxParameters = null; 

                // получить параметры алгоритма обмена
                if ((keyxParameters = TransportKeyAlgorithm(rand)) != null)
                try { 
                    // получить алгоритм транспорта ключа
                    IAlgorithm algorithm = factory.CreateAlgorithm<TransportKeyWrap>(scope, keyxParameters);

                    // проверить наличие алгоритма транспорта ключа
                    if (algorithm != null) { RefObject.Release(algorithm); return keyxParameters; } 
                }
                catch {}
            }
            // при допустимости согласования ключа
            if ((keyUsage & KeyUsage.KeyAgreement) != KeyUsage.None)
            {
                // создать список параметров 
                ASN1.ISO.AlgorithmIdentifier keyxParameters = null; 

                // получить параметры алгоритма согласования
                if ((keyxParameters = TransportAgreementAlgorithm(rand)) != null)
                try { 
                    // получить алгоритм согласования ключа
                    IAlgorithm algorithm = factory.CreateAlgorithm<ITransportAgreement>(scope, keyxParameters);

                    // проверить наличие алгоритма транспорта ключа
                    if (algorithm != null) { RefObject.Release(algorithm); return keyxParameters; }
                }
                catch {}
            }
            return null; 
        }
		///////////////////////////////////////////////////////////////////////
		// Зашифровать данные на открытом ключе (KeyX)
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.ContentInfo KeyxEncryptData(Culture culture, 
            Factory factory, SecurityStore scope, IRand rand, 
            Certificate recipientCertificate, CMSData data, ASN1.ISO.Attributes attributes)
		{
            // определить идентификатор ключа
            string keyOID = recipientCertificate.PublicKeyInfo.Algorithm.Algorithm.Value; 

            // указать используемые алгоритмы
            if (culture == null) culture = factory.GetCulture(scope, keyOID); 

            // проверить указание алгоритмов
            if (culture == null) throw new NotSupportedException(); 

            // зашифровать данные
            return Culture.KeyxEncryptData(culture, factory, scope, rand, 
                new Certificate[] { recipientCertificate }, 
                new Culture[] { culture }, data, attributes
            ); 
        }
		public static ASN1.ISO.PKCS.ContentInfo KeyxEncryptData(Culture culture, 
            Factory factory, SecurityStore scope, IRand rand, 
            Certificate[] recipientCertificates, Culture[] cultures,
            CMSData data, ASN1.ISO.Attributes attributes)
		{
            // проверить указание алгоритмов
            if (culture == null) throw new NotSupportedException(); 

            // указать идентификатор типа 
            ASN1.ObjectIdentifier dataType = new ASN1.ObjectIdentifier(
                ASN1.ISO.PKCS.PKCS7.OID.envelopedData
            ); 
            // создать список параметров 
            ASN1.ISO.AlgorithmIdentifier[] keyxParameters = 
                new ASN1.ISO.AlgorithmIdentifier[recipientCertificates.Length]; 

            // указать алгоритм шифрования
            ASN1.ISO.AlgorithmIdentifier cipherParameters = culture.CipherAlgorithm(rand); 

            // проверить указание параметров
            if (cipherParameters == null) throw new NotSupportedException(); 

            // для всех сертификатов
            for (int i = 0; i < keyxParameters.Length; i++)
            {
                // определить идентификатор ключа
                string keyOID = recipientCertificates[i].PublicKeyInfo.Algorithm.Algorithm.Value; 

                // указать используемые алгоритмы
                culture = (cultures != null) ? cultures[i] : null; 
                
                // указать используемые алгоритмы
                if (culture == null) culture = factory.GetCulture(scope, keyOID); 

                // проверить указание алгоритмов
                if (culture == null) throw new NotSupportedException(); 

                // получить параметры алгоритма
                keyxParameters[i] = culture.KeyxParameters(
                    factory, scope, rand, recipientCertificates[i].KeyUsage
                ); 
                // проверить отсутствие ошибок
                if (keyxParameters[i] == null) throw new NotSupportedException(); 
            }
            // зашифровать данные
            ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = CMS.KeyxEncryptData(
                factory, scope, rand, recipientCertificates, 
                cipherParameters, keyxParameters, data, attributes
            ); 
            // вернуть закодированную структуру
            return new ASN1.ISO.PKCS.ContentInfo(dataType, envelopedData); 
        }
	    public static ASN1.ISO.PKCS.ContentInfo KeyxEncryptData(
            Culture culture, IRand rand, IPrivateKey privateKey, 
            Certificate certificate, Certificate[] recipientCertificates, 
            Culture[] cultures, CMSData data, ASN1.ISO.Attributes attributes) 
	    {
            // определить идентификатор ключа
            string keyOID = certificate.PublicKeyInfo.Algorithm.Algorithm.Value; 

            // указать используемые алгоритмы
            if (culture == null) culture = privateKey.Factory.GetCulture(privateKey.Scope, keyOID); 

            // проверить указание алгоритмов
            if (culture == null) throw new NotSupportedException(); 

            // указать идентификатор типа 
            ASN1.ObjectIdentifier dataType = new ASN1.ObjectIdentifier(
                ASN1.ISO.PKCS.PKCS7.OID.envelopedData
            ); 
            // создать список параметров 
            ASN1.ISO.AlgorithmIdentifier[] keyxParameters = 
                new ASN1.ISO.AlgorithmIdentifier[recipientCertificates.Length]; 

            // получить параметры алгоритма шифрования
            ASN1.ISO.AlgorithmIdentifier cipherParameters = culture.CipherAlgorithm(rand);

            // проверить указание параметров
            if (cipherParameters == null) throw new NotSupportedException(); 
            
            // для всех сертификатов
            for (int i = 0; i < keyxParameters.Length; i++)
            {
                // определить идентификатор ключа
                keyOID = recipientCertificates[i].PublicKeyInfo.Algorithm.Algorithm.Value; 

                // указать используемые алгоритмы
                culture = (cultures != null) ? cultures[i] : null; 

                // указать используемые алгоритмы
                if (culture == null) culture = privateKey.Factory.GetCulture(privateKey.Scope, keyOID); 

                // проверить указание алгоритмов
                if (culture == null) throw new NotSupportedException(); 

                // получить параметры алгоритма
                keyxParameters[i] = culture.KeyxParameters( 
                    privateKey.Factory, privateKey.Scope, 
                    rand, recipientCertificates[i].KeyUsage
                ); 
                // проверить отсутствие ошибок
                if (keyxParameters[i] == null) throw new NotSupportedException(); 
            }
            // зашифровать данные
            ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = CMS.KeyxEncryptData( 
                rand, privateKey, certificate, recipientCertificates, 
                keyxParameters, cipherParameters, data, attributes
            ); 
            // вернуть закодированную структуру
            return new ASN1.ISO.PKCS.ContentInfo(dataType, envelopedData); 
        }
		///////////////////////////////////////////////////////////////////////
		// Подписать данные на личном ключе
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.ContentInfo SignData(Culture[] cultures, IRand rand, 
            IPrivateKey[] privateKeys, Certificate[] certificates, CMSData data, 
            ASN1.ISO.Attributes[] authAttributes, ASN1.ISO.Attributes[] unauthAttributes)
		{
            // скорректировать переданные параметры
            if (authAttributes   == null) authAttributes   = new ASN1.ISO.Attributes[privateKeys.Length];
            if (unauthAttributes == null) unauthAttributes = new ASN1.ISO.Attributes[privateKeys.Length];

            // указать идентификатор типа 
            ASN1.ObjectIdentifier dataType = new ASN1.ObjectIdentifier(
                ASN1.ISO.PKCS.PKCS7.OID.signedData
            ); 
	        // создать список параметров хэширования
	        ASN1.ISO.AlgorithmIdentifier[] hashParameters = 
                new ASN1.ISO.AlgorithmIdentifier[privateKeys.Length];

            // создать список параметров подписи
	        ASN1.ISO.AlgorithmIdentifier[] signHashParameters = 
                new ASN1.ISO.AlgorithmIdentifier[privateKeys.Length];

            // для всех личных ключей
            for (int i = 0; i < privateKeys.Length; i++)
            { 
                // определить идентификатор ключа
                string keyOID = certificates[i].PublicKeyInfo.Algorithm.Algorithm.Value; 

                // указать используемые алгоритмы
                Culture culture = (cultures != null) ? cultures[i] : null; 

                // указать используемые алгоритмы
                if (culture == null) culture = privateKeys[i].Factory.GetCulture(
                    privateKeys[i].Scope, keyOID
                ); 
                // проверить указание алгоритмов
                if (culture == null) throw new NotSupportedException(); 

                // получить параметры алгоритма хэширования
                hashParameters[i] = cultures[i].HashAlgorithm(rand); 

                // получить параметры алгоритма подписи
                signHashParameters[i] = cultures[i].SignHashAlgorithm(rand);

                // проверить наличие параметров
                if (hashParameters[i] == null || signHashParameters[i] == null)
                {
                    // при ошибке выбросить исключение
                    throw new NotSupportedException(); 
                }
            }
            // подписать данные
            ASN1.ISO.PKCS.PKCS7.SignedData signedData = CMS.SignData(
                rand, privateKeys, certificates, hashParameters, 
                signHashParameters, data, authAttributes, unauthAttributes
		    ); 
		    // вернуть закодированную структуру
		    return new ASN1.ISO.PKCS.ContentInfo(dataType, signedData); 
		}
		public static ASN1.ISO.PKCS.ContentInfo SignData(
            Culture culture, IRand rand, IPrivateKey privateKey, Certificate certificate, 
            CMSData data, ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes)
		{
            // определить идентификатор ключа
            string keyOID = certificate.PublicKeyInfo.Algorithm.Algorithm.Value; 

            // указать используемые алгоритмы
            if (culture == null) culture = privateKey.Factory.GetCulture(privateKey.Scope, keyOID); 

            // проверить указание алгоритмов
            if (culture == null) throw new NotSupportedException(); 

            // подписать данные
            return Culture.SignData(new Culture[] { culture }, rand, 
                new IPrivateKey[] { privateKey  }, 
                new Certificate[] { certificate }, data, 
                new ASN1.ISO.Attributes[] { authAttributes   },
                new ASN1.ISO.Attributes[] { unauthAttributes }
            ); 
		}
    }
}
