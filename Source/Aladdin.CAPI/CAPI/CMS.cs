using System;
using System.IO; 
using System.Collections.Generic;

namespace Aladdin.CAPI
{
	public static class CMS
	{
	    ///////////////////////////////////////////////////////////////////////
	    // Захэшировать данные
	    ///////////////////////////////////////////////////////////////////////
	    public static ASN1.ISO.PKCS.PKCS7.DigestedData HashData(Factory factory, SecurityStore scope, 
            ASN1.ISO.AlgorithmIdentifier parameters, CMSData data)
        {
		    // установить версию структуры
		    ASN1.Integer version = new ASN1.Integer(data.Type == ASN1.ISO.PKCS.PKCS7.OID.data ? 0 : 2); 

		    // закодировать хэшируемые данные
		    ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo encapContentInfo = 
                new ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo(
                    new ASN1.ObjectIdentifier(data.Type), new ASN1.OctetString(data.Content)
            ); 
		    // создать алгоритм хэширования данных
		    using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(scope, parameters))            
            {
                // при ошибке выбросить исключение
                if (hashAlgorithm == null) throw new NotSupportedException();
            
                // вычислить хэш-значение
                byte[] hash = hashAlgorithm.HashData(data.Content, 0, data.Content.Length); 
            
                // вернуть структуру 
                return new ASN1.ISO.PKCS.PKCS7.DigestedData(
                    version, parameters, encapContentInfo, new ASN1.OctetString(hash)
                ); 
            }
        }
	    public static CMSData VerifyHash(Factory factory, SecurityStore scope, 
            ASN1.ISO.PKCS.PKCS7.DigestedData digestedData)
        {
		    // извлечь содержимое
		    ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo encapContentInfo = digestedData.EncapContentInfo; 
        
            // проверить наличие содержимого
            if (encapContentInfo.EContent == null) throw new InvalidOperationException(); 
        
            // извлечь данные для хэширования и хэш-значение
            byte[] data = encapContentInfo.EContent.Value; byte[] check = digestedData.Digest.Value; 
        
		    // создать алгоритм хэширования данных
		    using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(scope, digestedData.DigestAlgorithm))
            {
                // при ошибке выбросить исключение
                if (hashAlgorithm == null) throw new NotSupportedException();
            
                // вычислить хэш-значение
                byte[] hash = hashAlgorithm.HashData(data, 0, data.Length); 
            
                // сравнить хэш-значение
                if (!Array.Equals(hash, check)) throw new IOException(); 
            
                // вернуть исходные данные
                return new CMSData(encapContentInfo.EContentType.Value, data); 
            }
        }
		///////////////////////////////////////////////////////////////////////
		// Зашифровать личный ключ на симметричном ключе
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo EncryptPrivateKey(
			Factory factory, SecurityStore scope, ISecretKey key, 
            ASN1.ISO.AlgorithmIdentifier parameters, 
            ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo)
		{
			// создать алгоритм шифрования данных
			using (Cipher cipher = factory.CreateAlgorithm<Cipher>(scope, parameters))
            { 
			    // при ошибке выбросить исключение
			    if (cipher == null) throw new NotSupportedException();

			    // извлечь зашифрованные данные
			    byte[] decrypted = privateKeyInfo.Encoded; 

			    // зашифровать данные
			    byte[] encrypted = cipher.Encrypt(
				    key, PaddingMode.PKCS5, decrypted, 0, decrypted.Length
			    );
			    // закодировать зашифрованные данные
			    return new ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo(
				    parameters, new ASN1.OctetString(encrypted)
			    );
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Расшифровать личный ключ на симметричном ключе
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo DecryptPrivateKey(
            Factory factory, SecurityStore scope, ISecretKey key, 
            ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo encryptedPrivateKeyInfo)
		{
			// получить параметры алгоритма шифрования
			ASN1.ISO.AlgorithmIdentifier parameters = encryptedPrivateKeyInfo.EncryptionAlgorithm; 

			// получить зашифрованные данные
			byte[] encrypted = encryptedPrivateKeyInfo.EncryptedData.Value;

			// создать алгоритм шифрования
			using (Cipher cipher = factory.CreateAlgorithm<Cipher>(scope, parameters))
            { 
			    // при ошибке выбросить исключение
			    if (cipher == null) throw new NotSupportedException();

			    // расшифровать данные
			    byte[] data = cipher.Decrypt(key, PaddingMode.PKCS5, encrypted, 0, encrypted.Length);

			    // вернуть закодированный ключ
			    return new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(ASN1.Encodable.Decode(data));
            } 
		}
		///////////////////////////////////////////////////////////////////////
		// Зашифровать личный ключ на ассиметричном ключе
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo EncryptPrivateKey(
            Factory factory, SecurityStore scope, IRand rand, 
            Certificate certificate, ASN1.ISO.AlgorithmIdentifier parameters, 
			ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo)
		{
            // извлечь открытый ключ сертификата
            IPublicKey publicKey = certificate.GetPublicKey(factory); 

            // создать алгоритм зашифрования
            using (Encipherment cipher = factory.CreateAlgorithm<Encipherment>(scope, parameters))
            {
                // при ошибке выбросить исключение
                if (cipher == null) throw new NotSupportedException();

                // зашифровать личный ключ
                byte[] encrypted = cipher.Encrypt(
                    publicKey, rand, privateKeyInfo.Encoded
                );
                // вернуть зашифрованный личный ключ
                return new ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo(
                    parameters, new ASN1.OctetString(encrypted)
                );
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Расшифровать личный ключ на ассиметричном ключе
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo DecryptPrivateKey(
			IPrivateKey privateKey, ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo encryptedPrivateKeyInfo)
		{
            // извлечь параметры шифрования
			ASN1.ISO.AlgorithmIdentifier parameters = encryptedPrivateKeyInfo.EncryptionAlgorithm; 

			// создать алгоритм расшифрования
			using (Decipherment cipher = privateKey.Factory.
                CreateAlgorithm<Decipherment>(privateKey.Scope, parameters))
            { 
			    // при ошибке выбросить исключение
			    if (cipher == null) throw new NotSupportedException();

			    // расшифровать личный ключ
			    byte[] decrypted = cipher.Decrypt(privateKey, 
				    encryptedPrivateKeyInfo.EncryptedData.Value); 

			    // вернуть расшифрованный личный ключ
			    return new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(ASN1.Encodable.Decode(decrypted)); 
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Зашифровать данные на симметричном ключе
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS7.EncryptedData EncryptData(
            Factory factory, SecurityStore scope, ISecretKey key, 
            ASN1.ISO.AlgorithmIdentifier parameters, 
            CMSData data, ASN1.ISO.Attributes unprotectedAttributes)
		{
			// создать алгоритм шифрования данных
			using (Cipher cipher = factory.CreateAlgorithm<Cipher>(scope, parameters))
            { 
			    // при ошибке выбросить исключение
			    if (cipher == null) throw new NotSupportedException(); byte[] encrypted = null; 

                // создать преобразование зашифрования
                using (Transform encryption = cipher.CreateEncryption(key, PaddingMode.PKCS5))
                {
                    // при наличии контроля целостности
                    if (encryption is TransformCheck)
                    {
                        // выделить память для атрибутов
                        List<ASN1.ISO.Attribute> listAttributes = new List<ASN1.ISO.Attribute>(); 
                        
                        // при наличии атрибутов
                        if (unprotectedAttributes != null) 
                        {
                            // добавить атрибуты в список
                            foreach (ASN1.ISO.Attribute attribute in unprotectedAttributes) 
                            {
                                listAttributes.Add(attribute);
                            }
                        }
                        // выполнить преобразование типа
                        TransformCheck encryptionCheck = (TransformCheck)encryption; 

                        // зашифровать данные
                        encrypted = encryptionCheck.TransformData(
                            data.Content, 0, data.Content.Length, listAttributes
                        ); 
                        // при наличии атрибутов
                        unprotectedAttributes = null; if (listAttributes.Count != 0)
                        {
                            // переустановить атрибуты
                            unprotectedAttributes = new ASN1.ISO.Attributes(listAttributes.ToArray()); 
                        }
                    }
                    // зашифровать данные
                    else encrypted = encryption.TransformData(data.Content, 0, data.Content.Length); 
                }
                // установить версию структуры
	            ASN1.Integer version = new ASN1.Integer(unprotectedAttributes == null ? 0 : 2); 

		        // закодировать зашифрованные данные
		        ASN1.ISO.PKCS.PKCS7.EncryptedContentInfo encryptedContentInfo = 
                    new ASN1.ISO.PKCS.PKCS7.EncryptedContentInfo(
       	                new ASN1.ObjectIdentifier(data.Type), 
                        parameters, new ASN1.OctetString(encrypted)
		        );
                // вернуть структруру
                return new ASN1.ISO.PKCS.PKCS7.EncryptedData(
                    version, encryptedContentInfo, unprotectedAttributes
                ); 
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Расшифровать данные на симметричном ключе
		///////////////////////////////////////////////////////////////////////
        public static CMSData DecryptData(Factory factory, SecurityStore scope, 
            ISecretKey key, ASN1.ISO.PKCS.PKCS7.EncryptedContentInfo encryptedContentInfo, 
            ASN1.ISO.Attributes unprotectedAttributes)
		{
			// получить параметры алгоритма шифрования
			ASN1.ISO.AlgorithmIdentifier parameters = encryptedContentInfo.ContentEncryptionAlgorithm; 

			// получить зашифрованные данные
			byte[] encrypted = encryptedContentInfo.EncryptedContent.Value;

			// создать алгоритм шифрования
			using (Cipher cipher = factory.CreateAlgorithm<Cipher>(scope, parameters))
            { 
			    // при ошибке выбросить исключение
			    if (cipher == null) throw new NotSupportedException(); byte[] data = null; 

                // получить преобразование расшифрования
                using (Transform decryption = cipher.CreateDecryption(key, PaddingMode.PKCS5))
                {
                    // при наличии контроля целостности
                    if (decryption is TransformCheck)
                    {
                        // выделить память для атрибутов
                        List<ASN1.ISO.Attribute> listAttributes = new List<ASN1.ISO.Attribute>(); 
                        
                        // при наличии атрибутов
                        if (unprotectedAttributes != null) 
                        {
                            // добавить атрибуты в список
                            foreach (ASN1.ISO.Attribute attribute in unprotectedAttributes) 
                            {
                                listAttributes.Add(attribute);
                            }
                        }
                        // выполнить преобразование типа
                        TransformCheck decryptionCheck = (TransformCheck)decryption; 

                        // расшифровать данные
                        data = decryptionCheck.TransformData(encrypted, 0, encrypted.Length, listAttributes); 
                    }
                    // расшифровать данные
                    else data = decryption.TransformData(encrypted, 0, encrypted.Length); 
                }
                // вернуть извлеченные данные
                return new CMSData(encryptedContentInfo.ContentType.Value, data);
            } 
		}
	    public static CMSData DecryptData(Factory factory, SecurityStore scope, 
            ISecretKey key, ASN1.ISO.PKCS.PKCS7.EncryptedData encryptedData) 
	    {
            // расшифровать данные
            return DecryptData(factory, scope, key, 
                encryptedData.EncryptedContentInfo, encryptedData.UnprotectedAttrs
            ); 
	    }
        public static CMSData DecryptData(Factory factory, SecurityStore scope, 
            ISecretKey key, byte[] keyID, ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData)
		{
            // закодировать идентификатор ключа
            ASN1.OctetString encodedKeyID = new ASN1.OctetString(keyID); 

			// получить информацию о зашифрованном ключе
			ASN1.ISO.PKCS.PKCS7.KEKRecipientInfo recipientInfo = 
				new ASN1.ISO.PKCS.PKCS7.KEKRecipientInfo(envelopedData.RecipientInfos[encodedKeyID]); 

			// получить параметры алгоритма шифрования
			ASN1.ISO.AlgorithmIdentifier cipherParametersKEK = recipientInfo.KeyEncryptionAlgorithm; 

            // извлечь зашифрованный ключ
            byte[] encryptedKey = recipientInfo.EncryptedKey.Content; 

			// создать алгоритм шифрования данных
			using (Cipher cipherKEK = factory.CreateAlgorithm<Cipher>(scope, cipherParametersKEK))
            { 
                // проверить наличие алгоритма
                if (cipherKEK == null) throw new NotSupportedException();

			    // расшифровать ключ шифрования данных
			    byte[] valueCEK = cipherKEK.Decrypt(
                    key, PaddingMode.PKCS5, encryptedKey, 0, encryptedKey.Length
                ); 
                // получить параметры алгоритма шифрования
                ASN1.ISO.AlgorithmIdentifier cipherParametersCEK = 
                    envelopedData.EncryptedContentInfo.ContentEncryptionAlgorithm; 
            
                // создать алгоритм шифрования
                using (Cipher cipherCEK = factory.CreateAlgorithm<Cipher>(scope, cipherParametersCEK))
                {
                    // при ошибке выбросить исключение
                    if (cipherCEK == null) throw new NotSupportedException();
            
                    // указать используемый ключ
                    using (ISecretKey CEK = cipherCEK.KeyFactory.Create(valueCEK))
                    {
				        // расшифровать данные
				        return CMS.DecryptData(factory, scope, CEK, 
                            envelopedData.EncryptedContentInfo, envelopedData.UnprotectedAttrs
                        ); 
                    }
                }
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Зашифровать ключ на пароле
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS7.PasswordRecipientInfo PasswordEncryptKey(
            Factory factory, SecurityStore scope, IRand rand, ISecretKey password, 
            ASN1.ISO.AlgorithmIdentifier keyDeriveParameters, 
			ASN1.ISO.AlgorithmIdentifier keyWrapParameters, ISecretKey CEK)
		{
			// создать алгоритм наследования ключа
			using (KeyDerive keyDerive = factory.CreateAlgorithm<KeyDerive>(scope, keyDeriveParameters))
            {
			    // при ошибке выбросить исключение
			    if (keyDerive == null) throw new NotSupportedException();

		        // создать алгоритм шифрования ключа
		        using (KeyWrap keyWrap = factory.CreateAlgorithm<KeyWrap>(scope, keyWrapParameters))
                { 
		            // при ошибке выбросить исключение
		            if (keyWrap == null) throw new NotSupportedException();  

                    // определить допустимые размеры ключей
                    int[] keySizes = keyWrap.KeyFactory.KeySizes; int keySize = -1; 
        
                    // указать рекомендуемый размер ключа
                    if (keySizes != null && keySizes.Length == 1) keySize = keySizes[0]; 

			        // создать ключ шифрования ключа
			        using (ISecretKey KEK = keyDerive.DeriveKey(password, null, keyWrap.KeyFactory, keySize))
			        {
                        // проверить допустимость размера ключа
                        if (!KeySizes.Contains(keySizes, KEK.Length)) 
                        {
                            // выбросить исключение
                            throw new InvalidOperationException();
                        }
                        // зашифровать ключ
                        byte[] encryptedKey = keyWrap.Wrap(rand, KEK, CEK);

                        // закодировать зашифрованный ключ с параметрами
                        return new ASN1.ISO.PKCS.PKCS7.PasswordRecipientInfo(
                            new ASN1.Integer(0), keyDeriveParameters,
                            keyWrapParameters, new ASN1.OctetString(encryptedKey)
                        );
                    }
                }
			}
		}
		///////////////////////////////////////////////////////////////////////
		// Расшифровать ключ на пароле
		///////////////////////////////////////////////////////////////////////
        public static ISecretKey PasswordDecryptKey(
            Factory factory, SecurityStore scope, ISecretKey password, 
            ASN1.ISO.PKCS.PKCS7.PasswordRecipientInfo recipientInfo, SecretKeyFactory keyFactory)
		{
			// получить информацию об алгоритме наследования ключа
			ASN1.ISO.AlgorithmIdentifier keyDeriveParameters = 
				recipientInfo.KeyDerivationAlgorithm;

			// получить информацию об алгоритме шифрования ключа
			ASN1.ISO.AlgorithmIdentifier keyWrapParameters = 
				recipientInfo.KeyEncryptionAlgorithm;
			
			// создать алгоритм наследования ключа
			using (KeyDerive keyDerive = factory.CreateAlgorithm<KeyDerive>(scope, keyDeriveParameters))
            { 
			    // при ошибке выбросить исключение
			    if (keyDerive == null) throw new NotSupportedException();

		        // создать алгоритм шифрования ключа
		        using (KeyWrap keyWrap = factory.CreateAlgorithm<KeyWrap>(scope, keyWrapParameters))
                 {
		            // при ошибке выбросить исключение
		            if (keyWrap == null) throw new NotSupportedException(); 

                    // определить допустимые размеры ключей
                    int[] keySizes = keyWrap.KeyFactory.KeySizes; int keySize = -1; 
        
                    // указать рекомендуемый размер ключа
                    if (keySizes != null && keySizes.Length == 1) keySize = keySizes[0]; 

			        // создать ключ шифрования ключа
			        using (ISecretKey KEK = keyDerive.DeriveKey(password, null, keyWrap.KeyFactory, keySize))
			        {
                        // проверить допустимость размера ключа
                        if (!KeySizes.Contains(keySizes, KEK.Length)) 
                        {
                            // выбросить исключение
                            throw new InvalidOperationException();
                        }
				        // расшифровать ключ
				        return keyWrap.Unwrap(KEK, recipientInfo.EncryptedKey.Value, keyFactory); 
			        }
                }
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Зашифровать данные по паролю
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS7.EnvelopedData PasswordEncryptData(
            Factory factory, SecurityStore scope, IRand rand, 
            ISecretKey[] passwords, ASN1.ISO.AlgorithmIdentifier cipherParameters, 
			ASN1.ISO.AlgorithmIdentifier[] keyDeriveParameters, 
			ASN1.ISO.AlgorithmIdentifier[] keyWrapParameters, 
			CMSData data, ASN1.ISO.Attributes attributes)
		{
			// создать алгоритм шифрования данных
			using (Cipher cipher = factory.CreateAlgorithm<Cipher>(scope, cipherParameters))
            { 
                // проверить наличие алгоритма
                if (cipher == null) throw new NotSupportedException();

                // определить допустимые размеры ключей
                int[] keySizes = cipher.KeyFactory.KeySizes; 
                
                // проверить наличие фиксированного размера
                if (keySizes == null || keySizes.Length != 1) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidOperationException();
                }
                // сгенерировать ключ
                using (ISecretKey CEK = cipher.KeyFactory.Generate(rand, keySizes[0]))
                {
                    // зашифровать данные на ключе
                    ASN1.ISO.PKCS.PKCS7.EncryptedData encryptedData = CMS.EncryptData(
                        factory, scope, CEK, cipherParameters, data, attributes
                    );
                    // создать список для зашифрованных ключей
                    List<ASN1.IEncodable> listRecipientInfos = new List<ASN1.IEncodable>();

                    // для каждого получателя
                    for (int i = 0; i < passwords.Length; i++)
                    {
                        // зашифровать ключ по паролю
                        ASN1.ISO.PKCS.PKCS7.PasswordRecipientInfo recipientInfo =
                            CMS.PasswordEncryptKey(factory, scope, rand, passwords[i],
                                keyDeriveParameters[i], keyWrapParameters[i], CEK
                        );
                        // поместить зашифрованный ключ в список
                        listRecipientInfos.Add(ASN1.Encodable.Encode(
                            ASN1.Tag.Context(3), recipientInfo.PC, recipientInfo.Content
                        ));
                    }
                    // закодировать список зашифрованных ключей
                    ASN1.ISO.PKCS.PKCS7.RecipientInfos recipientInfos =
                        new ASN1.ISO.PKCS.PKCS7.RecipientInfos(listRecipientInfos.ToArray());

                    // закодировать структуру CMS
                    return new ASN1.ISO.PKCS.PKCS7.EnvelopedData(
                        new ASN1.Integer(0), null, recipientInfos, 
                        encryptedData.EncryptedContentInfo, encryptedData.UnprotectedAttrs
                    );
                }
			}
		}
		///////////////////////////////////////////////////////////////////////
		// Расшифровать данные по паролю
		///////////////////////////////////////////////////////////////////////
        public static CMSData PasswordDecryptData(
            Factory factory, SecurityStore scope, ISecretKey password, 
            int index, ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData)
		{
			// извлечь зашифрованные данные
			ASN1.ISO.PKCS.PKCS7.EncryptedContentInfo encryptedContentInfo = 
				envelopedData.EncryptedContentInfo; 

			// получить информацию о зашифрованном ключе
			ASN1.ISO.PKCS.PKCS7.PasswordRecipientInfo recipientInfo = 
				new ASN1.ISO.PKCS.PKCS7.PasswordRecipientInfo(envelopedData.RecipientInfos[index]); 

		    // получить параметры алгоритма шифрования
		    ASN1.ISO.AlgorithmIdentifier cipherParameters = 
                encryptedContentInfo.ContentEncryptionAlgorithm; 
        
		    // создать алгоритм шифрования
		    using (CAPI.Cipher cipher = factory.CreateAlgorithm<CAPI.Cipher>(scope, cipherParameters))
            {
                // при ошибке выбросить исключение
                if (cipher == null) throw new NotSupportedException();
            
			    // расшифровать ключ шифрования данных по паролю
			    using (ISecretKey CEK = CMS.PasswordDecryptKey(
                    factory, scope, password, recipientInfo, cipher.KeyFactory)) 
			    {
				    // расшифровать данные
				    return CMS.DecryptData(factory, scope, CEK, 
                        encryptedContentInfo, envelopedData.UnprotectedAttrs
                    ); 
			    }
            }
		}
		public static CMSData PasswordDecryptData(
            Factory factory, SecurityStore scope, ISecretKey password, 
            ASN1.ISO.PKCS.ContentInfo contentInfo)
		{
            // в зависимости от идентификатора
            if (contentInfo.ContentType.Value == ASN1.ISO.PKCS.PKCS7.OID.encryptedData)
            {
                // раскодировать зашифрованные данные
                ASN1.ISO.PKCS.PKCS7.EncryptedData encryptedData = 
                    new ASN1.ISO.PKCS.PKCS7.EncryptedData(contentInfo.Inner); 

                // расшифровать данные
                return DecryptData(factory, scope, password, encryptedData); 
            }
            // в зависимости от идентификатора
            if (contentInfo.ContentType.Value == ASN1.ISO.PKCS.PKCS7.OID.envelopedData)
            {
                // раскодировать зашифрованные данные
                ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = 
                    new ASN1.ISO.PKCS.PKCS7.EnvelopedData(contentInfo.Inner); 

                // расшифровать данные
                return PasswordDecryptData(factory, scope, password, 0, envelopedData); 
            }
            // при ошибке выбросить исключение
            throw new NotSupportedException(); 
		}
		///////////////////////////////////////////////////////////////////////
		// Зашифровать ключ через алгоритм обмена
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS7.KeyTransRecipientInfo TransportEncryptKey(
            Factory factory, SecurityStore scope, IRand rand, 
            Certificate certificate, ASN1.Tag recipientChoice, 
            ASN1.ISO.AlgorithmIdentifier parameters, ISecretKey key)
		{
            // указать номер версии структуры
            ASN1.Integer version = new ASN1.Integer(0); ASN1.IEncodable rid = null; 

            // указать способ идентификации получателя
            if (recipientChoice == ASN1.Tag.Any) recipientChoice = ASN1.Tag.Sequence; 

            // указать способ идентификации получателя
            if (recipientChoice == ASN1.Tag.Sequence) rid = certificate.IssuerSerialNumber; 

            // в зависимости от способа идентификации
            else if (recipientChoice == ASN1.Tag.Context(0)) { version = new ASN1.Integer(2);
            
                // получить идентификатор ключа
                ASN1.OctetString subjectKeyIdentifier = certificate.SubjectKeyIdentifier; 

                // проверить наличие идентификатора
                if (subjectKeyIdentifier == null) throw new NotSupportedException(); 

                // закодировать идентификатор ключа
                rid = ASN1.Encodable.Encode(recipientChoice, 
                    subjectKeyIdentifier.PC, subjectKeyIdentifier.Content
                ); 
            }
            // извлечь открытый ключ сертификата
            IPublicKey publicKey = certificate.GetPublicKey(factory); 

			// создать алгоритм обмена ключа
			using (TransportKeyWrap keyTransport = factory.CreateAlgorithm<TransportKeyWrap>(scope, parameters))
            { 
			    // при ошибке выбросить исключение
			    if (keyTransport == null) throw new NotSupportedException();

                // зашифровать ключ шифрования данных
                TransportKeyData transportData = keyTransport.Wrap(
                    parameters, publicKey, rand, key
                );
                // закодировать зашифрованный ключ с параметрами
                return new ASN1.ISO.PKCS.PKCS7.KeyTransRecipientInfo(
                    version, rid, transportData.Algorithm, 
                    new ASN1.OctetString(transportData.EncryptedKey)
                );
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Расшифровать ключ через алгоритм обмена
		///////////////////////////////////////////////////////////////////////
		public static ISecretKey TransportDecryptKey(IPrivateKey privateKey, 
			ASN1.ISO.PKCS.PKCS7.KeyTransRecipientInfo recipientInfo, SecretKeyFactory keyFactory)
		{
            // получить информацию об используемом алгоритме
			ASN1.ISO.AlgorithmIdentifier parameters = recipientInfo.KeyEncryptionAlgorithm;

			// получить значение зашифрованного ключа
			ASN1.OctetString encryptedKey = recipientInfo.EncryptedKey;

            // создать алгоритм обмена
			using (TransportKeyUnwrap keyTransport = privateKey.Factory.
                CreateAlgorithm<TransportKeyUnwrap>(privateKey.Scope, parameters))
            {  
			    // при ошибке выбросить исключение
			    if (keyTransport == null) throw new NotSupportedException();

                // указать параметры траспортировки
                TransportKeyData transportData = new TransportKeyData(parameters, encryptedKey.Value); 

			    // вычислить ключ шифрования данных
			    return keyTransport.Unwrap(privateKey, transportData, keyFactory);
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Зашифровать ключ через алгоритм согласования
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo AgreementEncryptKey(
			IRand rand, IPrivateKey privateKey, IPublicKey publicKey, 
            ASN1.ISO.AlgorithmIdentifier parameters, 
            Certificate[] recipientCertificates, ISecretKey key)
		{
            // создать список открытых ключей
            IPublicKey[] recipientPublicKeys = new IPublicKey[recipientCertificates.Length]; 

            // для всех получателей
            for (int i = 0; i < recipientCertificates.Length; i++)
            {
                // получить способ использования ключа
                KeyUsage keyUsage = recipientCertificates[i].KeyUsage; 
        
                // проверить допустимость использования ключа
                if ((keyUsage & KeyUsage.DecipherOnly) != KeyUsage.None)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidOperationException(); 
                }
                // сохранить открытый ключ
                recipientPublicKeys[i] = recipientCertificates[i].GetPublicKey(privateKey.Factory); 
            }
            // выделить память для зашифрованных ключей
            ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKey[] recipientEncryptedKeys = 
	            new ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKey[recipientCertificates.Length]; 

            // создать алгоритм согласования ключа
			using (ITransportAgreement keyAgreement = privateKey.Factory.
                CreateAlgorithm<ITransportAgreement>(privateKey.Scope, parameters))
            { 
			    // при ошибке выбросить исключение
			    if (keyAgreement == null) throw new NotSupportedException();

                // зашифровать ключ для получателей
                TransportAgreementData data = keyAgreement.Wrap(
                    privateKey, publicKey, recipientPublicKeys, rand, key
                ); 
                // закодировать случайные данные
	            ASN1.OctetString ukm = (data.Random != null) ? new ASN1.OctetString(data.Random) : null; 

		        // для всех получателей
		        for (int i = 0; i < recipientCertificates.Length; i++)
		        {
                    // закодировать зашифрованный ключ
				    recipientEncryptedKeys[i] = new ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKey(
				        recipientCertificates[i].IssuerSerialNumber, 
                        new ASN1.OctetString(data.EncryptedKeys[i])
				    ); 
                }
                // закодировать открытый ключ
                ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = data.PublicKey.Encoded; 

                // указать способ идентификации отправителя
                ASN1.IEncodable originator = ASN1.Encodable.Encode(
                    ASN1.Tag.Context(1), publicKeyInfo.PC, publicKeyInfo.Content
                ); 
			    // закодировать зашифрованный ключ с параметрами
			    return new ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo(
				    new ASN1.Integer(3), originator, ukm, parameters, 
				    new ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKeys(recipientEncryptedKeys)
			    );
			}
		}
		public static ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo AgreementEncryptKey(
			IRand rand, IPrivateKey privateKey, Certificate certificate, 
            ASN1.Tag senderChoice, ASN1.ISO.AlgorithmIdentifier parameters, 
			Certificate[] recipientCertificates, ISecretKey key)
		{
            // указать используемый провайдер
            Factory factory = privateKey.Factory; ASN1.IEncodable originator = null; 

            // извлечь открытый ключ сертификата
            IPublicKey senderPublicKey = certificate.GetPublicKey(factory);

            // создать список открытых ключей
            IPublicKey[] recipientPublicKeys = new IPublicKey[recipientCertificates.Length]; 

            // для всех получателей
            for (int i = 0; i < recipientCertificates.Length; i++)
            {
                // получить способ использования ключа
                KeyUsage keyUsage = recipientCertificates[i].KeyUsage; 
        
                // проверить допустимость использования ключа
                if ((keyUsage & KeyUsage.DecipherOnly) != KeyUsage.None)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidOperationException(); 
                }
                // сохранить открытый ключ
                recipientPublicKeys[i] = recipientCertificates[i].GetPublicKey(privateKey.Factory); 
            }
            // создать алгоритм согласования ключа
			using (ITransportAgreement keyAgreement = privateKey.Factory.
                CreateAlgorithm<ITransportAgreement>(privateKey.Scope, parameters))
            { 
			    // при ошибке выбросить исключение
			    if (keyAgreement == null) throw new NotSupportedException();

                // зашифровать ключ для получателей
                TransportAgreementData data = keyAgreement.Wrap(
                    privateKey, senderPublicKey, recipientPublicKeys, rand, key
                ); 
	            // закодировать случайные данные
	            ASN1.OctetString ukm =  (data.Random != null) ? new ASN1.OctetString(data.Random) : null; 

	            // выделить память для зашифрованных ключей
                ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKey[] recipientEncryptedKeys = 
		            new ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKey[recipientCertificates.Length]; 

	            // для всех получателей
	            for (int i = 0; i < recipientCertificates.Length; i++)
	            {
			        // закодировать зашифрованный ключ
			        recipientEncryptedKeys[i] = new ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKey(
			            recipientCertificates[i].IssuerSerialNumber, 
                        new ASN1.OctetString(data.EncryptedKeys[i])
			        ); 
		        }
                // закодировать открытый ключ
                ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = data.PublicKey.Encoded; 

                // при отсутствии указания способа идентификации
                if (senderChoice == ASN1.Tag.Any) { senderChoice = ASN1.Tag.Sequence; 
                
                    // проверить допустимость способа
                    if (!certificate.PublicKeyInfo.Equals(publicKeyInfo)) senderChoice = ASN1.Tag.Context(1); 
                }
                // в зависимости от способа идентификации
                if (senderChoice == ASN1.Tag.Sequence) 
                {
                    // проверить допустимость способа
                    if (!certificate.PublicKeyInfo.Equals(publicKeyInfo)) throw new InvalidOperationException();

                    // указать способ идентификации отправителя
                    originator = certificate.IssuerSerialNumber; 
                }
                // в зависимости от способа идентификации
                else if (senderChoice == ASN1.Tag.Context(0))
                {
                    // проверить допустимость способа
                    if (!certificate.PublicKeyInfo.Equals(publicKeyInfo)) throw new InvalidOperationException();

                    // получить идентификатор ключа
                    ASN1.OctetString subjectKeyIdentifier = certificate.SubjectKeyIdentifier; 

                    // проверить наличие идентификатора
                    if (subjectKeyIdentifier == null) throw new NotSupportedException(); 

                    // закодировать идентификатор ключа
                    originator = ASN1.Encodable.Encode(
                        senderChoice, subjectKeyIdentifier.PC, subjectKeyIdentifier.Content
                    ); 
                }
                // в зависимости от способа идентификации
                else if (senderChoice == ASN1.Tag.Context(1))
                {
                    // указать способ идентификации отправителя
                    originator = ASN1.Encodable.Encode(
                        senderChoice, publicKeyInfo.PC, publicKeyInfo.Content
                    ); 
                }
                // при ошибке выбросить исключение
                else throw new NotSupportedException(); 

		        // закодировать зашифрованный ключ с параметрами
		        return new ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo(
			        new ASN1.Integer(3), originator, ukm, parameters, 
			        new ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKeys(recipientEncryptedKeys)
		        );
			}
		}
		///////////////////////////////////////////////////////////////////////
		// Расшифровать ключ через алгоритм согласования
		///////////////////////////////////////////////////////////////////////
		public static int FindCertificate(Certificate[] recipientCertificates, 
            ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo recipientInfo)
		{
			// получить информацию о зашифрованных ключах
			ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKeys encryptedKeys = 
				recipientInfo.RecipientEncryptedKeys; 

			// для каждого сертификата
			for (int i = 0; i < recipientCertificates.Length; i++)
			{
				// извлечь проверяемый сертификат
				Certificate recipientCertificate = recipientCertificates[i]; 

                // проверить наличие сертификата
                if (recipientCertificate == null) continue; 

				// найти информацию о ключе 
				if (encryptedKeys[recipientCertificate.Decoded] != null) return i; 
			}
			return -1; 
		}
		public static ISecretKey AgreementDecryptKey(IPrivateKey privateKey, 
            Certificate certificate, Certificate senderCertificate, 
            ASN1.ISO.PKCS.PKCS7.OriginatorInfo senderInfo, 
            ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo recipientInfo, SecretKeyFactory keyFactory)
		{
		    ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKey encryptedKey        = null; 
            ASN1.ISO.PKIX      .SubjectPublicKeyInfo  senderPublicKeyInfo = null; 

            // при указании сертификата
            if (certificate != null) { KeyUsage keyUsage = certificate.KeyUsage; 

                // проверить допустимость использования ключа
                if ((keyUsage & KeyUsage.EncipherOnly) != KeyUsage.None)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidOperationException(); 
                }
            }
		    // при указании идентификатора сертификата
            if (recipientInfo.Originator.Tag == ASN1.Tag.Sequence) 
            {
                // раскодировать идентификатор сертификата
                ASN1.ISO.PKIX.IssuerSerialNumber certID = 
                    new ASN1.ISO.PKIX.IssuerSerialNumber(recipientInfo.Originator); 

                // при наличии сертификата отправителя
                if (senderCertificate != null)
                {
                    // при совпадении идентификаторов сертификата
                    if (!senderCertificate.Decoded.TBSCertificate.IssuerSerialNumber.Equals(certID)) 
                    {
                        // при ошибке выбросить исключение
                        throw new NotSupportedException();
                    }
                }
                // при указании сертификата получателя
                else if (certificate != null) 
                {
                    // при совпадении идентификаторов сертификата
                    if (certificate.Decoded.TBSCertificate.IssuerSerialNumber.Equals(certID))
                    {
                        // указать сертификат отправителя
                        senderCertificate = certificate; 
                    }
                }
                // проверить наличии информации отправителя
                if (senderCertificate == null && senderInfo != null)
                { 
                    // получить список сертификатов отправителя
                    ASN1.ISO.CertificateSet senderCertificates = senderInfo.Certs;
            
                    // для всех сертификатов
                    if (senderCertificates != null) foreach (ASN1.IEncodable encodable in senderCertificates)
                    {
                        // проверить указание сертификата X.509
                        if (encodable.Tag != ASN1.Tag.Sequence) continue; 
                
                        // раскодировать сертификат
                        ASN1.ISO.PKIX.Certificate senderCert = new ASN1.ISO.PKIX.Certificate(encodable);
                
                        // проверить совпадение идентификаторов
                        if (senderCertificate.TBSCertificate.IssuerSerialNumber.Equals(certID))
                        {
                            // указать сертификат отправителя
                            senderCertificate = new Certificate(senderCert.Encoded); break; 
                        }
                    }
                }
            }
		    // при указании идентификатора ключа
            else if (recipientInfo.Originator.Tag == ASN1.Tag.Context(0)) 
            {
                // раскодировать идентификатор ключа
                ASN1.OctetString keyID = new ASN1.OctetString(recipientInfo.Originator); 

                // при наличии сертификата отправителя
                if (senderCertificate != null)
                {
                    // извлечь расширения сертификата
                    ASN1.ISO.PKIX.Extensions extensions = senderCertificate.Decoded.TBSCertificate.Extensions; 

                    // получить идентификатор ключа
                    ASN1.OctetString id = (extensions != null) ? extensions.SubjectKeyIdentifier : null; 

                    // проверить совпадение идентификатора
                    if (id == null || !keyID.Equals(id)) throw new NotSupportedException();
                }
                // при указании сертификата получателя
                else if (certificate != null) 
                {
                    // извлечь расширения сертификата
                    ASN1.ISO.PKIX.Extensions extensions = certificate.Decoded.TBSCertificate.Extensions; 

                    // получить идентификатор ключа
                    ASN1.OctetString id = (extensions != null) ? extensions.SubjectKeyIdentifier : null; 

                    // проверить совпадение идентификатора
                    if (id != null || keyID.Equals(id)) senderCertificate = certificate; 
                }
                // проверить наличии информации отправителя
                if (senderCertificate == null && senderInfo != null)
                { 
                    // получить список сертификатов отправителя
                    ASN1.ISO.CertificateSet senderCertificates = senderInfo.Certs;
            
                    // для всех сертификатов
                    if (senderCertificates == null) foreach (ASN1.IEncodable encodable in senderCertificates)
                    {
                        // проверить указание сертификата X.509
                        if (encodable.Tag != ASN1.Tag.Sequence) continue; 
                
                        // раскодировать сертификат
                        ASN1.ISO.PKIX.Certificate senderCert = new ASN1.ISO.PKIX.Certificate(encodable);

                        // извлечь расширения сертификата
                        ASN1.ISO.PKIX.Extensions extensions = senderCertificate.TBSCertificate.Extensions; 

                        // получить идентификатор ключа
                        ASN1.OctetString id = (extensions != null) ? extensions.SubjectKeyIdentifier : null; 
                
                        // проверить совпадение идентификатора
                        if (id != null && keyID.Equals(id))
                        {
                            // указать сертификат отправителя
                            senderCertificate = new Certificate(senderCert.Encoded); break; 
                        }
                    }
                }
            }
            // при явном указании открытого ключа
            else if (recipientInfo.Originator.Tag == ASN1.Tag.Context(1))
            {
                // раскодировать открытый ключ 
                senderPublicKeyInfo = new ASN1.ISO.PKIX.SubjectPublicKeyInfo(recipientInfo.Originator);

                // извлечь параметры ключа
                ASN1.IEncodable keyParameters = senderPublicKeyInfo.Algorithm.Parameters; 

                // при отсутствии параметров ключа
                if ((keyParameters == null || keyParameters.Content.Length == 0))
                {
                    // при наличии сертификата отправителя
                    if (senderCertificate != null)
                    {
                        // закодировать открытый ключ
                        senderPublicKeyInfo = new ASN1.ISO.PKIX.SubjectPublicKeyInfo(
                            senderCertificate.PublicKeyInfo.Algorithm, 
                            senderPublicKeyInfo.SubjectPublicKey
                        ); 
                    }
                    // проверить наличие сертификата получателя 
                    else if (certificate != null) 
                    {
                        // закодировать открытый ключ
                        senderPublicKeyInfo = new ASN1.ISO.PKIX.SubjectPublicKeyInfo(
                            certificate.PublicKeyInfo.Algorithm, 
                            senderPublicKeyInfo.SubjectPublicKey
                        ); 
                    }
                }
            }
            // при наличии сертификата отправителя
            if (senderPublicKeyInfo == null && senderCertificate != null)
            {
                // указать открытый ключ
                senderPublicKeyInfo = senderCertificate.Decoded.TBSCertificate.SubjectPublicKeyInfo;
            }
            // проверить наличие открытого ключа
            if (senderPublicKeyInfo == null) throw new NotFoundException();

			// раскодировать открытый ключ
			IPublicKey senderPublicKey = privateKey.Factory.DecodePublicKey(senderPublicKeyInfo);
 
			// получить информацию о зашифрованных ключах
			ASN1.ISO.PKCS.PKCS7.RecipientEncryptedKeys encryptedKeys = 
				recipientInfo.RecipientEncryptedKeys; 

            // найти информацию о ключе по сертификату 
            if (certificate != null) encryptedKey = encryptedKeys[certificate.Decoded]; 
            
            // найти информацию о ключе
            else if (encryptedKeys.Length == 1) encryptedKey = encryptedKeys[0]; 

			// проверить нахождение информации о подписи 
			if (encryptedKey == null) throw new NotFoundException();

			// извлечь случайные данные
			byte[] random = (recipientInfo.Ukm != null) ? recipientInfo.Ukm.Value : null; 

			// получить информацию об используемом алгоритме 
			ASN1.ISO.AlgorithmIdentifier parameters = recipientInfo.KeyEncryptionAlgorithm;

            // создать алгоритм согласования
			using (ITransportAgreement keyAgreement = privateKey.Factory.
                CreateAlgorithm<ITransportAgreement>(privateKey.Scope, parameters))
            { 
 			    // при ошибке выбросить исключение
			    if (keyAgreement == null) throw new NotSupportedException();

			    // вычислить ключ шифрования данных
			    return keyAgreement.Unwrap(privateKey, senderPublicKey, 
                    random, encryptedKey.EncryptedKey.Value, keyFactory
			    ); 
            }
		}
        ///////////////////////////////////////////////////////////////////////
		// Зашифровать ключ для получателей
		///////////////////////////////////////////////////////////////////////
        public static ASN1.ISO.PKCS.PKCS7.RecipientInfos KeyxEncryptKey(
            Factory factory, SecurityStore scope, IRand rand, ISecretKey key, 
            Certificate[] recipientCertificates, ASN1.ISO.AlgorithmIdentifier[] keyxParameters)
        {
            // создать список использований ключа
            KeyUsage[] recipientUsages = new KeyUsage[recipientCertificates.Length]; 

            // заполнить список использования ключа
            for (int i = 0; i < recipientCertificates.Length; i++)
            {
                // указать использование ключа
                recipientUsages[i] = recipientCertificates[i].KeyUsage; 
            }
		    // зашифровать ключ для получателей
            return KeyxEncryptKey(factory, scope, rand, key, 
                recipientCertificates, recipientUsages, keyxParameters
            ); 
        }
        public static ASN1.ISO.PKCS.PKCS7.RecipientInfos KeyxEncryptKey(
            Factory factory, SecurityStore scope, IRand rand, ISecretKey key, 
            Certificate[] recipientCertificates, KeyUsage[] recipientUsages, 
            ASN1.ISO.AlgorithmIdentifier[] keyxParameters)
        {
            // создать список для зашифрованных ключей
            List<ASN1.IEncodable> listRecipientInfos = new List<ASN1.IEncodable>(); 

			// для каждого получателя
			for (int i = 0; i < recipientCertificates.Length; i++)
			{
                // при допустимости транспорта ключа
                if ((recipientUsages[i] & KeyUsage.KeyEncipherment) != KeyUsage.None)
                {
                    // получить алгоритм транспорта ключа
                    IAlgorithm algorithm = factory.
                        CreateAlgorithm<TransportKeyWrap>(scope, keyxParameters[i]);

                    // при наличии алгоритма транспорта ключа
                    if (algorithm != null) { RefObject.Release(algorithm); 

                        // зашифровать ключ шифрования данных
                        ASN1.ISO.PKCS.PKCS7.KeyTransRecipientInfo recipientInfo = 
                            CMS.TransportEncryptKey(factory, scope, rand,  
                                recipientCertificates[i], 
                                ASN1.Tag.Any, keyxParameters[i], key
                        );
                        // поместить зашифрованный ключ в список
                        listRecipientInfos.Add(recipientInfo); continue; 
                    }
                }
                // при допустимости согласования ключа
                if ((recipientUsages[i] & (KeyUsage.KeyEncipherment | KeyUsage.KeyAgreement)) != KeyUsage.None)
                {
                    // получить алгоритм согласования ключа
                    IAlgorithm algorithm = factory.
                        CreateAlgorithm<ITransportAgreement>(scope, keyxParameters[i]); 

                    // при наличии алгоритма согласования ключа
                    if (algorithm != null) { RefObject.Release(algorithm);

                        // извлечь открытый ключ получателя
                        IPublicKey publicKey = recipientCertificates[i].GetPublicKey(factory); 

                        // создать алгоритм генерации ключей
                        using (KeyPairGenerator generator = factory.CreateGenerator(
                            null, rand, publicKey.KeyOID, publicKey.Parameters))
                        {  
                            // сгенерировать эфемерную пару ключей
                            using (KeyPair keyPair = generator.Generate(null, 
                                publicKey.KeyOID, KeyUsage.KeyAgreement, KeyFlags.None))
                            {
                                // зашифровать ключ шифрования данных
                                ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo recipientInfo = 
                                    CMS.AgreementEncryptKey(rand, keyPair.PrivateKey, 
                                        keyPair.PublicKey, keyxParameters[i], 
                                        new Certificate[] { recipientCertificates[i] }, key 
                                );
                                // поместить зашифрованный ключ в список
                                listRecipientInfos.Add(ASN1.Encodable.Encode(
                                    ASN1.Tag.Context(1), recipientInfo.PC, recipientInfo.Content
                                )); 
                                continue; 
                            }
                        }
                    }
                }
                // при ошибке выбросить исключение
                throw new NotSupportedException(); 
			}
			// закодировать список зашифрованных ключей
			return new ASN1.ISO.PKCS.PKCS7.RecipientInfos(listRecipientInfos.ToArray());
        }
        public static ASN1.ISO.PKCS.PKCS7.RecipientInfos KeyxEncryptKey(
            IRand rand, IPrivateKey privateKey, Certificate[] certificateChain, ISecretKey key, 
            Certificate[] recipientCertificates, ASN1.ISO.AlgorithmIdentifier[] keyxParameters, 
            out ASN1.ISO.PKCS.PKCS7.OriginatorInfo originatorInfo)
        {
            // создать список использований ключа
            KeyUsage[] recipientUsages = new KeyUsage[recipientCertificates.Length]; 

            // заполнить список использования ключа
            for (int i = 0; i < recipientCertificates.Length; i++)
            {
                // указать использование ключа
                recipientUsages[i] = recipientCertificates[i].KeyUsage; 
            }
		    // зашифровать ключ для получателей
            return KeyxEncryptKey(rand, privateKey, certificateChain, key, 
                recipientCertificates, recipientUsages, keyxParameters, out originatorInfo
            ); 
        }
        public static ASN1.ISO.PKCS.PKCS7.RecipientInfos KeyxEncryptKey(
            IRand rand, IPrivateKey privateKey, Certificate[] certificateChain, ISecretKey key, 
            Certificate[] recipientCertificates, KeyUsage[] recipientUsages, 
            ASN1.ISO.AlgorithmIdentifier[] keyxParameters, out ASN1.ISO.PKCS.PKCS7.OriginatorInfo originatorInfo)
        {
            // создать список для зашифрованных ключей
            List<ASN1.IEncodable> listRecipientInfos = new List<ASN1.IEncodable>(); originatorInfo = null;

            // для каждого получателя
            for (int i = 0; i < recipientCertificates.Length; i++)
	        {
                // при допустимости транспорта ключа
                if ((recipientUsages[i] & KeyUsage.KeyEncipherment) != KeyUsage.None)
                {
                    // получить алгоритм транспорта ключа
                    IAlgorithm algorithm = privateKey.Factory.
                        CreateAlgorithm<TransportKeyWrap>(privateKey.Scope, keyxParameters[i]
                    );
                    // при наличии алгоритма транспорта ключа
                    if (algorithm != null) { RefObject.Release(algorithm);
            
                        // зашифровать ключ шифрования данных
                        ASN1.ISO.PKCS.PKCS7.KeyTransRecipientInfo recipientInfo =
                            CMS.TransportEncryptKey(privateKey.Factory, 
                                privateKey.Scope, rand, recipientCertificates[i], 
                                ASN1.Tag.Any, keyxParameters[i], key
                        );
                        // поместить зашифрованный ключ в список
                        listRecipientInfos.Add(recipientInfo); continue; 
                    }
                }
                // при допустимости согласования ключа
                if ((recipientUsages[i] & (KeyUsage.KeyEncipherment | KeyUsage.KeyAgreement)) != KeyUsage.None)
                {
                    // проверить допустимость операции
                    // if ((certificateChain[0].KeyUsage & (KeyUsage.KeyEncipherment | KeyUsage.KeyAgreement)) == KeyUsage.None)
                    // {
                    //     // при ошибке выбросить исключение
                    //     throw new NotSupportedException(); 
                    // }
                    // получить алгоритм согласования ключа
                    IAlgorithm algorithm = privateKey.Factory.
                        CreateAlgorithm<ITransportAgreement>(privateKey.Scope, keyxParameters[i]
                    ); 
                    // при наличии алгоритма согласования ключа
                    if (algorithm != null) { RefObject.Release(algorithm); 
            
                        // создать список закодированных представлений
                        ASN1.IEncodable[] encodables = new ASN1.IEncodable[certificateChain.Length]; 

                        // для каждого сертификата
                        for (int j = 0; j < certificateChain.Length; j++) 
                        {
                            // сохранить закодированное представление
                            encodables[j] = certificateChain[j].Decoded; 
                        }
                        // указать набор сертификатов отправителя
                        ASN1.ISO.CertificateSet certificates = new ASN1.ISO.CertificateSet(encodables); 

                        // указать отправителя
                        originatorInfo = new ASN1.ISO.PKCS.PKCS7.OriginatorInfo(certificates, null); 
            
                        // зашифровать ключ шифрования данных
                        ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo recipientInfo = 
                            CMS.AgreementEncryptKey(rand, privateKey, 
                            certificateChain[0], ASN1.Tag.Any, keyxParameters[i], 
                            new Certificate[] { recipientCertificates[i] }, key
                        );
                        // поместить зашифрованный ключ в список
                        listRecipientInfos.Add(ASN1.Encodable.Encode(
                            ASN1.Tag.Context(1), recipientInfo.PC, recipientInfo.Content
                        )); 
                        continue; 
                    }
                }
                // при ошибке выбросить исключение
                throw new NotSupportedException(); 
            }
		    // закодировать список зашифрованных ключей
		    return new ASN1.ISO.PKCS.PKCS7.RecipientInfos(listRecipientInfos.ToArray());
        }
        ///////////////////////////////////////////////////////////////////////
		// Расшифровать ключ для получателя
		///////////////////////////////////////////////////////////////////////
		public static Certificate FindCertificate(IEnumerable<Certificate> recipientCertificates, 
            ASN1.ISO.PKCS.PKCS7.RecipientInfos recipientInfos)
		{
			// для кажлго сертификата
			foreach (Certificate certificate in recipientCertificates)
			{
                // проверить наличие сертификата
                if (certificate == null) continue; 

				// найти информацию о ключе
				if (recipientInfos[certificate.Decoded] != null) return certificate;
			}
			return null; 
		}
		public static ISecretKey KeyxDecryptKey<T>(IPrivateKey privateKey, 
            Certificate certificate, Certificate senderCertificate, 
            ASN1.ISO.PKCS.PKCS7.OriginatorInfo originatorInfo, 
            ASN1.ISO.AlgorithmIdentifier parameters, ASN1.IEncodable recipientInfo) where T : IAlgorithm
		{
            // фабрика создания симметричных ключей
            SecretKeyFactory keyFactory = null; 

            // создать алгоритм шифрования или выработки имтовставки
            using (T algorithm = privateKey.Factory.CreateAlgorithm<T>(privateKey.Scope, parameters))
            {
                // при ошибке выбросить исключение
                if (algorithm == null) throw new NotSupportedException();

                // получить фабрику создания алгоритма
                if (algorithm is Cipher) { keyFactory = (algorithm as Cipher).KeyFactory; } else 
                if (algorithm is Mac   ) { keyFactory = (algorithm as Mac   ).KeyFactory; } 
                
                // при ошибке выбросить исключение
                else throw new InvalidOperationException(); 

                // в зависимости от типа дапнных
                if (recipientInfo is ASN1.ISO.PKCS.PKCS7.KeyTransRecipientInfo)
                {
                    // преобразовать тип данных
                    ASN1.ISO.PKCS.PKCS7.KeyTransRecipientInfo keyTransRecipientInfo = 
                        (ASN1.ISO.PKCS.PKCS7.KeyTransRecipientInfo)recipientInfo; 

                    // расшифровать ключ шифрования данных
                    return CMS.TransportDecryptKey(privateKey, keyTransRecipientInfo, keyFactory); 
                }
                // в зависимости от типа дапнных
                else if (recipientInfo is ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo)
                {
                    // преобразовать тип данных
                    ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo keyAgreeRecipientInfo = 
                        (ASN1.ISO.PKCS.PKCS7.KeyAgreeRecipientInfo)recipientInfo; 

                    // расшифровать ключ шифрования данных
                    return CMS.AgreementDecryptKey(privateKey, certificate, 
                        senderCertificate, originatorInfo, keyAgreeRecipientInfo, keyFactory
                    ); 
                }
                // при ошибке выбросить исключение
                else throw new NotSupportedException();
            }
		}
        ///////////////////////////////////////////////////////////////////////
	    // Вычислить имитовставку через алгоритм обмена или согласования
	    ///////////////////////////////////////////////////////////////////////
        public static ASN1.ISO.PKCS.PKCS9.AuthenticatedData KeyxMacData(Factory factory, 
            SecurityStore scope, IRand rand, Certificate[] recipientCertificates, 
		    ASN1.ISO.AlgorithmIdentifier[] keyxParameters, ASN1.ISO.AlgorithmIdentifier macParameters, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, CMSData data, 
            ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes)
        {
            // создать список использований ключа
            KeyUsage[] recipientUsages = new KeyUsage[recipientCertificates.Length]; 

            // заполнить список использования ключа
            for (int i = 0; i < recipientCertificates.Length; i++)
            {
                // указать использование ключа
                recipientUsages[i] = recipientCertificates[i].KeyUsage; 
            }
	        // вычислить имитовставку через алгоритм обмена или согласования
            return KeyxMacData(factory, scope, rand, recipientCertificates, recipientUsages, 
                keyxParameters, macParameters, hashParameters, data, authAttributes, unauthAttributes
            ); 
        }
        public static ASN1.ISO.PKCS.PKCS9.AuthenticatedData KeyxMacData(
            Factory factory, SecurityStore scope, IRand rand, 
            Certificate[] recipientCertificates, KeyUsage[] recipientUsages, 
		    ASN1.ISO.AlgorithmIdentifier[] keyxParameters, ASN1.ISO.AlgorithmIdentifier macParameters, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, CMSData data, 
            ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes)
        {
            // закодировать исходные данные
            ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo encapContentInfo = 
                new ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo(
                    new ASN1.ObjectIdentifier(data.Type), new ASN1.OctetString(data.Content)
            ); 
            // указать данные для имитовставки
            byte[] macData = data.Content; 
        
            // при наличии защищаемых атрибутов
            if (authAttributes != null && authAttributes.Length > 0)
            {
                // проверить указание алгоритма хэширования
                if (hashParameters == null) throw new InvalidOperationException(); 
            
                // создать алгоритм хэширования
                using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(scope, hashParameters))
                {
                    // при ошибке выбросить исключение
                    if (hashAlgorithm == null) throw new NotSupportedException();

                    // захэшировать данные
                    byte[] hash = hashAlgorithm.HashData(data.Content, 0, data.Content.Length);

                    // извлечь тип данных
                    string dataType = encapContentInfo.EContentType.Value; 

                    // указать идентификатор типа содержимого
                    ASN1.Set<ASN1.ObjectIdentifier> contentType = 
                        new ASN1.Set<ASN1.ObjectIdentifier>(
                            new ASN1.ObjectIdentifier[] { new ASN1.ObjectIdentifier(dataType) }
                    );
                    // указать хэш-значение
                    ASN1.Set<ASN1.OctetString> messageDigest = 
                        new ASN1.Set<ASN1.OctetString>(
                            new ASN1.OctetString[] { new ASN1.OctetString(hash) }
                    );
                    // создать атрибут для типа содержимого
                    ASN1.ISO.Attribute attrContentType = new ASN1.ISO.Attribute(
                        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.contentType), contentType
                    ); 
                    // создать атрибут для хэш-значения
                    ASN1.ISO.Attribute attrMessageDigest = new ASN1.ISO.Attribute(
                        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.messageDigest), messageDigest
                    ); 
                    // выделить память для атрибутов
                    List<ASN1.ISO.Attribute> listAttributes = new List<ASN1.ISO.Attribute>(); 

                    // добавить атрибуты типа содержимого и хэш-значения
                    listAttributes.Add(attrContentType  ); 
                    listAttributes.Add(attrMessageDigest); 

                    // добавить оставшиеся атрибуты в список
                    foreach (ASN1.ISO.Attribute attribute in authAttributes) listAttributes.Add(attribute);

                    // переустановить аутентифицируемые атрибуты
                    authAttributes = new ASN1.ISO.Attributes(listAttributes.ToArray()); 

                    // закодировать атрибуты
                    macData = authAttributes.Encoded; 
                }
            }
		    // создать алгоритм вычисления имитовставки
		    using (Mac macAlgorithm = factory.CreateAlgorithm<Mac>(scope, macParameters))
            {
                // проверить наличие алгоритма
                if (macAlgorithm == null) throw new NotSupportedException();
            
                // определить допустимые размеры ключей
                int[] keySizes = macAlgorithm.KeyFactory.KeySizes; 
                
                // проверить наличие фиксированного размера ключа
                if (keySizes == null || keySizes.Length != 1) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidOperationException();
                }
                // преобразовать тип ключа
                using (ISecretKey key = macAlgorithm.KeyFactory.Generate(rand, keySizes[0])) 
                { 
                    // разделить ключ между получателями
                    ASN1.ISO.PKCS.PKCS7.RecipientInfos recipientInfos = KeyxEncryptKey(
                        factory, scope, rand, key, recipientCertificates, recipientUsages, keyxParameters
                    ); 
                    // вычислить имитовстаку
                    ASN1.OctetString mac = new ASN1.OctetString(macAlgorithm.MacData(
                        key, macData, 0, macData.Length
                    )); 
                    // закодировать структуру CMS
                    return new ASN1.ISO.PKCS.PKCS9.AuthenticatedData(new ASN1.Integer(0), 
                        null, recipientInfos, macParameters, hashParameters, 
                        encapContentInfo, authAttributes, mac, unauthAttributes
                    );
                }
            }
        }
        public static ASN1.ISO.PKCS.PKCS9.AuthenticatedData KeyxMacData(IRand rand, 
            IPrivateKey privateKey, Certificate[] certificateChain, Certificate[] recipientCertificates, 
		    ASN1.ISO.AlgorithmIdentifier[] keyxParameters, ASN1.ISO.AlgorithmIdentifier macParameters, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, CMSData data, 
            ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes)
        {
            // создать список использований ключа
            KeyUsage[] recipientUsages = new KeyUsage[recipientCertificates.Length]; 

            // заполнить список использования ключа
            for (int i = 0; i < recipientCertificates.Length; i++)
            {
                // указать использование ключа
                recipientUsages[i] = recipientCertificates[i].KeyUsage; 
            }
	        // вычислить имитовставку через алгоритм обмена или согласования
            return KeyxMacData(rand, privateKey, certificateChain, recipientCertificates, recipientUsages, 
                keyxParameters, macParameters, hashParameters, data, authAttributes, unauthAttributes
            ); 
        }
        public static ASN1.ISO.PKCS.PKCS9.AuthenticatedData KeyxMacData(
            IRand rand, IPrivateKey privateKey, Certificate[] certificateChain, 
            Certificate[] recipientCertificates, KeyUsage[] recipientUsages, 
		    ASN1.ISO.AlgorithmIdentifier[] keyxParameters, ASN1.ISO.AlgorithmIdentifier macParameters, 
            ASN1.ISO.AlgorithmIdentifier hashParameters, CMSData data, 
            ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes)
        {
            // закодировать исходные данные
            ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo encapContentInfo = 
                new ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo(
                    new ASN1.ObjectIdentifier(data.Type), new ASN1.OctetString(data.Content)
            ); 
            // указать данные для имитовставки
            byte[] macData = data.Content; 
        
            // при наличии защищаемых атрибутов
            if (authAttributes != null && authAttributes.Length > 0)
            {
                // проверить указание алгоритма хэширования
                if (hashParameters == null) throw new InvalidOperationException(); 
            
                // создать алгоритм хэширования
                using (Hash hashAlgorithm = privateKey.Factory.CreateAlgorithm<Hash>(privateKey.Scope, hashParameters))
                {
                    // при ошибке выбросить исключение
                    if (hashAlgorithm == null) throw new NotSupportedException();

                    // захэшировать данные
                    byte[] hash = hashAlgorithm.HashData(data.Content, 0, data.Content.Length);

                    // извлечь тип данных
                    string dataType = encapContentInfo.EContentType.Value; 

                    // указать идентификатор типа содержимого
                    ASN1.Set<ASN1.ObjectIdentifier> contentType = 
                        new ASN1.Set<ASN1.ObjectIdentifier>(
                            new ASN1.ObjectIdentifier[] { new ASN1.ObjectIdentifier(dataType) }
                    );
                    // указать хэш-значение
                    ASN1.Set<ASN1.OctetString> messageDigest = 
                        new ASN1.Set<ASN1.OctetString>(
                            new ASN1.OctetString[] { new ASN1.OctetString(hash) }
                    );
                    // создать атрибут для типа содержимого
                    ASN1.ISO.Attribute attrContentType = new ASN1.ISO.Attribute(
                        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.contentType), contentType
                    ); 
                    // создать атрибут для хэш-значения
                    ASN1.ISO.Attribute attrMessageDigest = new ASN1.ISO.Attribute(
                        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.messageDigest), messageDigest
                    ); 
                    // выделить память для атрибутов
                    List<ASN1.ISO.Attribute> listAttributes = new List<ASN1.ISO.Attribute>(); 

                    // добавить атрибуты типа содержимого и хэш-значения
                    listAttributes.Add(attrContentType  ); 
                    listAttributes.Add(attrMessageDigest); 

                    // добавить оставшиеся атрибуты в список
                    foreach (ASN1.ISO.Attribute attribute in authAttributes) listAttributes.Add(attribute);

                    // переустановить аутентифицируемые атрибуты
                    authAttributes = new ASN1.ISO.Attributes(listAttributes.ToArray()); 

                    // закодировать атрибуты
                    macData = authAttributes.Encoded; 
                }
            }
		    // создать алгоритм вычисления имитовставки
		    using (Mac macAlgorithm = privateKey.Factory.CreateAlgorithm<Mac>(privateKey.Scope, macParameters))
            {
                // проверить наличие алгоритма
                if (macAlgorithm == null) throw new NotSupportedException();
            
                // определить допустимые размеры ключей
                int[] keySizes = macAlgorithm.KeyFactory.KeySizes; 
                
                // проверить наличие фиксированного размера ключа
                if (keySizes == null || keySizes.Length != 1) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidOperationException();
                }
                // преобразовать тип ключа
                using (ISecretKey key = macAlgorithm.KeyFactory.Generate(rand, keySizes[0])) 
                { 
                    // данные отправителя
                    ASN1.ISO.PKCS.PKCS7.OriginatorInfo originatorInfo = null; 
            
                    // разделить ключ между получателями
                    ASN1.ISO.PKCS.PKCS7.RecipientInfos recipientInfos = KeyxEncryptKey(
                        rand, privateKey, certificateChain, key, recipientCertificates, 
                        recipientUsages, keyxParameters, out originatorInfo
                    ); 
                    // вычислить имитовстаку
                    ASN1.OctetString mac = new ASN1.OctetString(macAlgorithm.MacData(
                        key, macData, 0, macData.Length
                    )); 
                    // установить версию структуры
                    ASN1.Integer version = new ASN1.Integer(originatorInfo != null ? 1 : 0); 
                
                    // закодировать структуру CMS
                    return new ASN1.ISO.PKCS.PKCS9.AuthenticatedData(version, 
                        originatorInfo, recipientInfos, macParameters, hashParameters, 
                        encapContentInfo, authAttributes, mac, unauthAttributes
                    );
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////
	    // Проверить имитовставку через алгоритм обмена или согласования
	    ///////////////////////////////////////////////////////////////////////
	    public static Certificate FindCertificate(IEnumerable<Certificate> recipientCertificates, 
            ASN1.ISO.PKCS.PKCS9.AuthenticatedData authenticatedData)
	    {
            // найти требуемый сертификат
            return FindCertificate(recipientCertificates, authenticatedData.RecipientInfos); 
	    }
        public static CMSData KeyxVerifyMac(IPrivateKey privateKey, Certificate certificate, 
            Certificate senderCertificate, ASN1.ISO.PKCS.PKCS9.AuthenticatedData authenticatedData)
        {
            // при наличии сертификата
            ASN1.IEncodable recipientInfo = null; if (certificate != null)
		    {
			    // найти информацию о ключе 
			    recipientInfo = authenticatedData.RecipientInfos[certificate.Decoded];
            }
		    // при наличии информации
		    else if (authenticatedData.RecipientInfos.Length == 1)
		    {
			    // найти информацию 
			    recipientInfo = authenticatedData.RecipientInfos[0];
		    }
		    // проверить нахождение информации 
		    if (recipientInfo == null) throw new NotFoundException(); 

		    // извлечь защищаемые данные
		    ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo 
                encapsulatedContentInfo = authenticatedData.EncapContentInfo; 

		    // извлечь данные для проверки
		    byte[] content = encapsulatedContentInfo.EContent.Value; 
			
		    // извлечь имитовставку
		    byte[] check = authenticatedData.Mac.Value; byte[] hash = null;

		    // определить данные для проверки имитовставки
		    byte[] macData = content; byte[] hashData = null; 
        
            // извлечь защищаемые атрибуты
            ASN1.ISO.Attributes authAttributes = authenticatedData.AuthAttrs;

            // проверить наличие атрибутов
            if (authAttributes != null && authAttributes.Length > 0) 
            {
                string contentType = null; List<ASN1.ISO.Attribute> listAttributes = new List<ASN1.ISO.Attribute>(); 
            
                // проверить указание алгоритма хэширования
                if (authenticatedData.DigestAlgorithm == null) throw new IOException();

                // для всех подписанных атрибутов
                foreach (ASN1.ISO.Attribute attribute in authAttributes)
                {
                    // извлечь идентификатор атрибута
                    string oid = attribute.Type.Value; listAttributes.Add(attribute);

                    // для атрибута типа данных
                    if (oid == ASN1.ISO.PKCS.PKCS9.OID.contentType)
                    {
                        // извлечь тип данных
                        contentType = new ASN1.Set<ASN1.ObjectIdentifier>(attribute.Values)[0].Value;
                    }
                    // для атрибута хэш-значения
                    else if (oid == ASN1.ISO.PKCS.PKCS9.OID.messageDigest)
                    {
                        // извлечь хэш-значение
                        hash = new ASN1.Set<ASN1.OctetString>(attribute.Values)[0].Value;
                    }
                }
                // проверить корректность структуры
                if (contentType == null || hash == null) throw new IOException();

                // проверить совпадение типа данных
                if (encapsulatedContentInfo.EContentType.Value != contentType)
                {
                    // при ошибке выбросить исключение
                    throw new IOException();
                }
                // переустановить аутентифицируемые атрибуты
                authAttributes = new ASN1.ISO.Attributes(listAttributes.ToArray()); 
            
                // определить данные для проверки подписи
                macData = authAttributes.Encoded; hashData = content;
            }
            // получить параметры вычисления имитовставки
            ASN1.ISO.AlgorithmIdentifier macParameters = authenticatedData.MacAlgorithm; 
        
		    // создать алгоритм вычисления имитовставки
		    using (Mac macAlgorithm = privateKey.Factory.CreateAlgorithm<Mac>(privateKey.Scope, macParameters))
            {
                // проверить наличие алгоритма
                if (macAlgorithm == null) throw new NotSupportedException();
            
                // расшифровать ключ выработки имитовставки
                using (ISecretKey key = KeyxDecryptKey<Mac>(privateKey, certificate, 
                    senderCertificate, authenticatedData.OriginatorInfo, macParameters, recipientInfo))
                {
                    // вычислить имитовставку
                    byte[] mac = macAlgorithm.MacData(key, macData, 0, macData.Length); 
                
                    // проверить совпадение имитовставок
                    if (!Arrays.Equals(mac, check)) throw new IOException(); 
                }
            }
            // при наличии защищаемых атрибутов
            if (hashData != null && hash != null)
            {
                // создать алгоритм хэширования
                using (Hash hashAlgorithm = privateKey.Factory.CreateAlgorithm<Hash>(
                    privateKey.Scope, authenticatedData.DigestAlgorithm))
                {
                    // проверить наличие алгоритма
                    if (hashAlgorithm == null) throw new NotSupportedException();

                    // вычислить хэш-значение
                    check = hashAlgorithm.HashData(hashData, 0, hashData.Length);

                    // проверить совпадение хэш-значений
                    if (!Arrays.Equals(hash, check)) throw new IOException();
                }
            }
            // вернуть исходные данные
            return new CMSData(encapsulatedContentInfo.EContentType.Value, content); 
        }
        ///////////////////////////////////////////////////////////////////////
		// Зашифровать данные через алгоритм обмена или согласования
		///////////////////////////////////////////////////////////////////////
        public static ASN1.ISO.PKCS.PKCS7.EnvelopedData KeyxEncryptData(
            Factory factory, SecurityStore scope, IRand rand, 
            Certificate[] recipientCertificates, 
			ASN1.ISO.AlgorithmIdentifier[] keyxParameters, 
            ASN1.ISO.AlgorithmIdentifier cipherParameters, 
            CMSData data, ASN1.ISO.Attributes attributes)
        {
            // создать список использований ключа
            KeyUsage[] recipientUsages = new KeyUsage[recipientCertificates.Length]; 

            // заполнить список использования ключа
            for (int i = 0; i < recipientCertificates.Length; i++)
            {
                // указать использование ключа
                recipientUsages[i] = recipientCertificates[i].KeyUsage; 
            }
		    // зашифровать данные через алгоритм обмена или согласования
            return KeyxEncryptData(factory, scope, rand, recipientCertificates, 
                recipientUsages, keyxParameters, cipherParameters, data, attributes
            ); 
        }
        public static ASN1.ISO.PKCS.PKCS7.EnvelopedData KeyxEncryptData(
            Factory factory, SecurityStore scope, IRand rand, 
            Certificate[] recipientCertificates, KeyUsage[] recipientUsages, 
			ASN1.ISO.AlgorithmIdentifier[] keyxParameters, 
            ASN1.ISO.AlgorithmIdentifier cipherParameters, 
            CMSData data, ASN1.ISO.Attributes attributes)
		{
			// создать алгоритм шифрования данных
			using (Cipher cipher = factory.CreateAlgorithm<Cipher>(scope, cipherParameters))
            { 
                // проверить наличие алгоритма
                if (cipher == null) throw new NotSupportedException();
        
                // определить допустимые размеры ключей
                int[] keySizes = cipher.KeyFactory.KeySizes; 
                
                // проверить наличие фиксированного размера ключа
                if (keySizes == null || keySizes.Length != 1)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidOperationException();
                }
			    // сгенерировать ключ
			    using (ISecretKey CEK = cipher.KeyFactory.Generate(rand, keySizes[0]))
			    {
		            // разделить ключ между получателями
                    ASN1.ISO.PKCS.PKCS7.RecipientInfos recipientInfos = KeyxEncryptKey(
                        factory, scope, rand, CEK, 
                        recipientCertificates, recipientUsages, keyxParameters
                    ); 
			        // зашифровать данные
			        ASN1.ISO.PKCS.PKCS7.EncryptedData encryptedData = CMS.EncryptData(
                        factory, scope, CEK, cipherParameters, data, attributes
                    );
			        // закодировать структуру CMS
			        return new ASN1.ISO.PKCS.PKCS7.EnvelopedData(
                        new ASN1.Integer(0), null, recipientInfos, 
                        encryptedData.EncryptedContentInfo, encryptedData.UnprotectedAttrs
                    );
                }
            }
		}
        public static ASN1.ISO.PKCS.PKCS7.EnvelopedData KeyxEncryptData(
            IRand rand, IPrivateKey privateKey, Certificate[] certificateChain, 
            Certificate[] recipientCertificates, 
            ASN1.ISO.AlgorithmIdentifier[] keyxParameters, 
            ASN1.ISO.AlgorithmIdentifier cipherParameters, 
            CMSData data, ASN1.ISO.Attributes attributes)
        {
            // создать список использований ключа
            KeyUsage[] recipientUsages = new KeyUsage[recipientCertificates.Length]; 

            // заполнить список использования ключа
            for (int i = 0; i < recipientCertificates.Length; i++)
            {
                // указать использование ключа
                recipientUsages[i] = recipientCertificates[i].KeyUsage; 
            }
		    // зашифровать данные через алгоритм обмена или согласования
            return KeyxEncryptData(rand, privateKey, certificateChain, recipientCertificates, 
                recipientUsages, keyxParameters, cipherParameters, data, attributes
            ); 
        }
        public static ASN1.ISO.PKCS.PKCS7.EnvelopedData KeyxEncryptData(
            IRand rand, IPrivateKey privateKey, Certificate[] certificateChain, 
            Certificate[] recipientCertificates, KeyUsage[] recipientUsages, 
            ASN1.ISO.AlgorithmIdentifier[] keyxParameters, 
            ASN1.ISO.AlgorithmIdentifier cipherParameters, 
            CMSData data, ASN1.ISO.Attributes attributes)
        {
            // создать алгоритм шифрования данных
		    using (Cipher cipher = privateKey.Factory.
                CreateAlgorithm<Cipher>(privateKey.Scope, cipherParameters))
            { 
                // проверить наличие алгоритма
                if (cipher == null) throw new NotSupportedException();

                // определить допустимые размеры ключей
                int[] keySizes = cipher.KeyFactory.KeySizes; 
                
                // проверить наличие фиксированного размера ключа
                if (keySizes == null || keySizes.Length != 1)
                {
                    // при ошибке выбросить исключение
                    throw new InvalidOperationException();
                }
                // сгенерировать ключ
                using (ISecretKey CEK = cipher.KeyFactory.Generate(rand, keySizes[0]))
                { 
                    // данные отправителя
                    ASN1.ISO.PKCS.PKCS7.OriginatorInfo originatorInfo = null;

		            // разделить ключ между получателями
                    ASN1.ISO.PKCS.PKCS7.RecipientInfos recipientInfos = KeyxEncryptKey(
                        rand, privateKey, certificateChain, CEK, 
                        recipientCertificates, recipientUsages, keyxParameters, out originatorInfo
                    ); 
                    // зашифровать данные
                    ASN1.ISO.PKCS.PKCS7.EncryptedData encryptedData = CMS.EncryptData(
                        privateKey.Factory, privateKey.Scope, CEK, cipherParameters, data, attributes
                    );
                    // закодировать структуру CMS
		            return new ASN1.ISO.PKCS.PKCS7.EnvelopedData(
                        new ASN1.Integer(0), originatorInfo, recipientInfos, 
                        encryptedData.EncryptedContentInfo, encryptedData.UnprotectedAttrs
                    );
                }
            }
        }
		///////////////////////////////////////////////////////////////////////
		// Расшифровать данные через алгоритм обмена или согласования
		///////////////////////////////////////////////////////////////////////
		public static Certificate FindCertificate(IEnumerable<Certificate> recipientCertificates, 
            ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData)
		{
            // найти требуемый сертификат
            return FindCertificate(recipientCertificates, envelopedData.RecipientInfos); 
		}
		public static CMSData KeyxDecryptData(IPrivateKey privateKey, 
            Certificate certificate, Certificate senderCertificate, 
            ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData)
		{
            // при наличии сертификата
            ASN1.IEncodable recipientInfo = null; if (certificate != null)
		    {
			    // найти информацию о ключе 
			    recipientInfo = envelopedData.RecipientInfos[certificate.Decoded];
            }
		    // при наличии информации
		    else if (envelopedData.RecipientInfos.Length == 1)
		    {
			    // найти информацию 
			    recipientInfo = envelopedData.RecipientInfos[0];
		    }
		    // проверить нахождение информации 
		    if (recipientInfo == null) throw new NotFoundException(); 

            // получить параметры алгоритма шифрования
            ASN1.ISO.AlgorithmIdentifier cipherParameters = 
                envelopedData.EncryptedContentInfo.ContentEncryptionAlgorithm; 

            // расшифровать ключ шифрования данных
            using (ISecretKey CEK = KeyxDecryptKey<Cipher>(privateKey, certificate, 
                senderCertificate, envelopedData.OriginatorInfo, cipherParameters, recipientInfo))
            {
                // расшифровать данные
                return CMS.DecryptData(privateKey.Factory, privateKey.Scope,
                    CEK, envelopedData.EncryptedContentInfo, envelopedData.UnprotectedAttrs
                );
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Подписать данные
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS7.SignerInfo SignData( 
			IRand rand, IPrivateKey privateKey, Certificate certificate,   
			ASN1.ISO.AlgorithmIdentifier hashParameters, 
			ASN1.ISO.AlgorithmIdentifier signHashParameters, 
			ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo encapContentInfo, 
			ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes)
		{
            // извлечь данные
            byte[] data = encapContentInfo.EContent.Value;

            // создать алгоритм хэширования
			using (Hash hashAlgorithm = privateKey.Factory.
                CreateAlgorithm<Hash>(privateKey.Scope, hashParameters))
            { 
			    // при ошибке выбросить исключение
			    if (hashAlgorithm == null) throw new NotSupportedException();

			    // захэшировать данные
			    byte[] hash = hashAlgorithm.HashData(data, 0, data.Length);

			    // при наличии подписываемых атрибутов
			    if (authAttributes != null && authAttributes.Length > 0)
			    {
				    // извлечь тип данных
				    string dataType = encapContentInfo.EContentType.Value; 

				    // указать идентификатор типа содержимого
				    ASN1.Set<ASN1.ObjectIdentifier> contentType = new ASN1.Set<ASN1.ObjectIdentifier>(
					    new ASN1.ObjectIdentifier[] { new ASN1.ObjectIdentifier(dataType) }
				    );
				    // указать хэш-значение
				    ASN1.Set<ASN1.OctetString> messageDigest = new ASN1.Set<ASN1.OctetString>(
					    new ASN1.OctetString[] { new ASN1.OctetString(hash) }
				    );
				    // создать атрибут для типа содержимого
				    ASN1.ISO.Attribute attrContentType = new ASN1.ISO.Attribute(
					    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.contentType), contentType
				    ); 
				    // создать атрибут для хэш-значения
				    ASN1.ISO.Attribute attrMessageDigest = new ASN1.ISO.Attribute(
					    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.messageDigest), messageDigest
				    ); 
				    // выделить память для атрибутов
				    List<ASN1.ISO.Attribute> listAttributes = 
					    new List<ASN1.ISO.Attribute>(); 

				    // добавить атрибуты типа содержимого и хэш-значения
				    listAttributes.Add(attrContentType  ); 
				    listAttributes.Add(attrMessageDigest); 
 
				    // добавить оставшиеся атрибуты в список
				    listAttributes.AddRange(authAttributes);

                    // переустановить аутентифицируемые атрибуты
                    authAttributes = new ASN1.ISO.Attributes(listAttributes.ToArray()); 
				
				    // закодировать атрибуты
				    byte[] encoded = authAttributes.Encoded; 
				
				    // захэшировать атрибуты
				    hash = hashAlgorithm.HashData(encoded, 0, encoded.Length);
			    }
                // создать алгоритм подписи
                using (SignHash signAlgorithm = privateKey.Factory.
                    CreateAlgorithm<SignHash>(privateKey.Scope, signHashParameters))
                { 
                    // при ошибке выбросить исключение
                    if (signAlgorithm == null) throw new NotSupportedException();

                    // подписать хэш-значение
                    ASN1.OctetString signature = new ASN1.OctetString(
                        signAlgorithm.Sign(privateKey, rand, hashParameters, hash)
                    );
                    // извлечь параметры сертификата
	                ASN1.ISO.AlgorithmIdentifier certParameters = certificate.PublicKeyInfo.Algorithm; 

	                // закодировать информацию подписывающего лица
	                return new ASN1.ISO.PKCS.PKCS7.SignerInfo(new ASN1.Integer(1), 
                        certificate.IssuerSerialNumber, hashParameters, 
	                    authAttributes, certParameters, signature, unauthAttributes
	                ); 
                }
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Подписать данные
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS7.SignedData SignData(IRand rand, 
			IPrivateKey[] privateKeys, Certificate[][] certificatesChains,   
			ASN1.ISO.AlgorithmIdentifier[] hashParameters, 
			ASN1.ISO.AlgorithmIdentifier[] signHashParameters, CMSData data, 
			ASN1.ISO.Attributes[] authAttributes, ASN1.ISO.Attributes[] unauthAttributes)
		{
			// установить версию структуры
			ASN1.Integer version = new ASN1.Integer(data.Type == ASN1.ISO.PKCS.PKCS7.OID.data ? 1 : 3); 

			// закодировать подписываемые данные
			ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo encapContentInfo = 
				new ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo(
					new ASN1.ObjectIdentifier(data.Type), new ASN1.OctetString(data.Content)
			); 
			// создать список алгоритмов хэширования
			List<ASN1.ISO.AlgorithmIdentifier> listHashAlgorithms = new 
				List<ASN1.ISO.AlgorithmIdentifier>();
 
			// создать список сертификатов
			List<ASN1.IEncodable> listCertificates = new List<ASN1.IEncodable>(); 

			// создать список подписанных данных
			List<ASN1.ISO.PKCS.PKCS7.SignerInfo> listSignerInfos = 
				new List<ASN1.ISO.PKCS.PKCS7.SignerInfo>(); 

			// для каждого подписывающего лица
			for (int i = 0; i < privateKeys.Length; i++)
			{
                // при отсутствии алгоритма хэширования
                if (!listHashAlgorithms.Contains(hashParameters[i]))
                {
                    // добавить указанный алгоритм в список
                    listHashAlgorithms.Add(hashParameters[i]); 
                }
                // для всех сертификатов цепочки
                foreach (Certificate certificate in certificatesChains[i])
                {
                    // при отсутствиии сертификата
                    if (!listCertificates.Contains(certificate.Decoded))
                    {
                        // добавить сертификат в список
                        listCertificates.Add(certificate.Decoded); 
                    }
                }
				// подписать данные
				ASN1.ISO.PKCS.PKCS7.SignerInfo signerInfo = SignData( 
					rand, privateKeys[i], certificatesChains[i][0], 
					hashParameters[i], signHashParameters[i], encapContentInfo, 
					authAttributes[i], unauthAttributes[i]
				); 
				// добавить подписанные данные в список
				listSignerInfos.Add(signerInfo); 
			}
			// закодировать алгоритмы хэширования
			ASN1.ISO.AlgorithmIdentifiers hashAlgorithms = 
				new ASN1.ISO.AlgorithmIdentifiers(listHashAlgorithms.ToArray());
 
			// закодировать используемые сертификаты
			ASN1.ISO.CertificateSet certificateSet = 
				new ASN1.ISO.CertificateSet(listCertificates.ToArray());
 
			// закодировать подписанные данные из списка
			ASN1.ISO.PKCS.PKCS7.SignerInfos signerInfos = 
				new ASN1.ISO.PKCS.PKCS7.SignerInfos(listSignerInfos.ToArray());

			// вернуть закодированные данные
			return new ASN1.ISO.PKCS.PKCS7.SignedData(version, hashAlgorithms, 
				encapContentInfo, certificateSet, null, signerInfos
			); 
		}
		///////////////////////////////////////////////////////////////////////
		// Проверить подпись данных
		///////////////////////////////////////////////////////////////////////
		public static Certificate FindCertificate(IEnumerable<Certificate> certificates, 
            ASN1.ISO.PKCS.PKCS7.SignedData signedData)
		{
			// для кажлго сертификата
			foreach (Certificate certificate in certificates)
			{
                // проверить наличие сертификата
                if (certificate == null) continue; 

				// получить идентификатор сертификата
				ASN1.ISO.PKIX.IssuerSerialNumber certID = certificate.IssuerSerialNumber; 

				// при наличии идентификатора ключа
				if (certificate.SubjectKeyIdentifier != null) 
				{
					// получить идентификатор ключа
					ASN1.OctetString keyID = certificate.SubjectKeyIdentifier; 

					// найти информацию о подписи по идентификатору
					if (signedData.SignerInfos[keyID] != null) return certificate; 
				}
				// найти информацию о подписи 
				if (signedData.SignerInfos[certID] != null) return certificate; 
			}
			return null; 
		}
		public static ASN1.ISO.PKCS.PKCS7.SignerInfo VerifySign(
            Factory factory, SecurityStore scope, 
            Certificate certificate, ASN1.ISO.PKCS.PKCS7.SignedData signedData)
		{
            // получить способ использования ключа
            ASN1.ISO.PKCS.PKCS7.SignerInfo signerInfo = null;
        
            // извлечь открытый ключ сертификата
            IPublicKey publicKey = certificate.GetPublicKey(factory); 

			// получить идентификатор сертификата
			ASN1.ISO.PKIX.IssuerSerialNumber certID = certificate.IssuerSerialNumber; 

			// при наличии идентификатора ключа
			if (certificate.SubjectKeyIdentifier != null) 
			{
				// получить идентификатор ключа
				ASN1.OctetString keyID = certificate.SubjectKeyIdentifier; 

				// найти информацию о подписи по идентификатору
				signerInfo = signedData.SignerInfos[keyID]; 
			}
			// найти информацию о подписи 
			if (signerInfo == null) signerInfo = signedData.SignerInfos[certID]; 

			// проверить нахождение информации о подписи 
			if (signerInfo == null) throw new NotFoundException();

			// извлечь подписанные данные
			ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo encapsulatedContentInfo = 
				signedData.EncapContentInfo; 

			// извлечь данные для проверки
			byte[] content = encapsulatedContentInfo.EContent.Value; 
				
			// извлечь подпись
			byte[] signature = signerInfo.Signature.Value;

			// определить данные для проверки подписи
			byte[] signData = content; byte[] hashData = null; byte[] hash = null;

			// извлечь подписанные атрибуты
			ASN1.ISO.Attributes signedAttributes = signerInfo.SignedAttrs;

			// проверить наличие атрибутов
			if (signedAttributes != null && signedAttributes.Length > 0) 
			{
				string contentType = null; List<ASN1.ISO.Attribute> listAttributes = new List<ASN1.ISO.Attribute>(); 

				// для всех подписанных атрибутов
				foreach (ASN1.ISO.Attribute attribute in signedAttributes)
				{
					// извлечь идентификатор атрибута
					string oid = attribute.Type.Value; listAttributes.Add(attribute); 

					// для атрибута типа данных
					if (oid == ASN1.ISO.PKCS.PKCS9.OID.contentType)
					{
						// извлечь тип данных
						contentType = new ASN1.Set<ASN1.ObjectIdentifier>(attribute.Values)[0].Value;
					}
					// для атрибута хэш-значения
					else if (oid == ASN1.ISO.PKCS.PKCS9.OID.messageDigest)
					{
						// извлечь хэш-значение
						hash = new ASN1.Set<ASN1.OctetString>(attribute.Values)[0].Value;
					}
				}
				// проверить корректность структуры
				if (contentType == null || hash == null) throw new InvalidDataException();

				// проверить совпадение типа данных
				if (encapsulatedContentInfo.EContentType.Value != contentType)
				{
					// при ошибке выбросить исключение
					throw new InvalidDataException();
				}
                // переустановить аутентифицируемые атрибуты
                signedAttributes = new ASN1.ISO.Attributes(listAttributes.ToArray()); 

				// определить данные для проверки подписи
				signData = signedAttributes.Encoded; hashData = content;
			}
			// раскодировать параметры алгоритма хэширования
			ASN1.ISO.AlgorithmIdentifier hashParameters = signerInfo.DigestAlgorithm;

			// раскодировать параметры алгоритма подписи
			ASN1.ISO.AlgorithmIdentifier signParameters = signerInfo.SignatureAlgorithm;

			// создать алгоритм хэширования
			using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(scope, hashParameters))
            { 
			    // при ошибке выбросить исключение
			    if (hashAlgorithm == null) throw new NotSupportedException();

                // захэшировать данные
                byte[] check = hashAlgorithm.HashData(signData, 0, signData.Length);

                // создать алгоритм подписи
			    using (VerifyHash verifyAlgorithm = factory.CreateAlgorithm<VerifyHash>(scope, signParameters))
                { 
			        // при ошибке выбросить исключение
			        if (verifyAlgorithm == null) throw new NotSupportedException();

			        // проверить подпись хэш-значения
			        verifyAlgorithm.Verify(publicKey, hashParameters, check, signature); 
                }
			    // проверить наличие атрибутов
			    if (hashData != null && hash != null)
			    {
				    // вычислить хэш-значение
				    check = hashAlgorithm.HashData(hashData, 0, hashData.Length);

				    // проверить совпадение хэш-значений
				    if (!Arrays.Equals(hash, check)) throw new SignatureException();
			    }
            }
			return signerInfo; 
		}
	}
}
