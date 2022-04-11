using System;
using System.Text;
using System.Security.Authentication; 

namespace Aladdin.CAPI.PKCS12
{
	public static class Pfx
	{
	    ///////////////////////////////////////////////////////////////////////
        // Создать контейнер
	    ///////////////////////////////////////////////////////////////////////
        public static ASN1.ISO.PKCS.PKCS12.PFX CreateContainer( 
            Factory factory, ASN1.ISO.PKCS.PKCS12.AuthenticatedSafe authenticatedSafe) 
        { 
            // указать идентификатор данных
			string dataType = ASN1.ISO.PKCS.PKCS7.OID.data; 
        
		    // закодировать данные
		    byte[] encoded = authenticatedSafe.Encoded;  

            // закодировать данные
            ASN1.ISO.PKCS.ContentInfo contentInfo = new ASN1.ISO.PKCS.ContentInfo(
                new ASN1.ObjectIdentifier(dataType), new ASN1.OctetString(encoded)
            ); 
            // закодировать контейнер
            return new ASN1.ISO.PKCS.PKCS12.PFX(new ASN1.Integer(3), contentInfo, null); 
        }
		///////////////////////////////////////////////////////////////////////
		// Создать подписанный контейнер PKCS12
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS12.PFX CreateSignedContainer(
			Factory factory, IRand rand, ASN1.Integer version,
			ASN1.ISO.PKCS.PKCS12.AuthenticatedSafe authenticatedSafe,  
			IPrivateKey privateKey, Certificate certificate, 
			ASN1.ISO.AlgorithmIdentifier hashParameters, 
			ASN1.ISO.AlgorithmIdentifier signParameters, 
			ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes, 
			ASN1.ISO.CertificateSet certificates, ASN1.ISO.RevocationInfoChoices crls)
		{
			// указать тип данных
			string dataType = ASN1.ISO.PKCS.PKCS7.OID.data; 

			// указать алгоритмы хэширования
			ASN1.ISO.AlgorithmIdentifiers digestAlgorithms = 
				new ASN1.ISO.AlgorithmIdentifiers(
                    new ASN1.ISO.AlgorithmIdentifier[] { hashParameters }
            ); 
			// создать вложенные данные
			ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo encapContentInfo = 
				new ASN1.ISO.PKCS.PKCS7.EncapsulatedContentInfo(
					new ASN1.ObjectIdentifier(dataType), 
                    new ASN1.OctetString(authenticatedSafe.Encoded)
			); 
			// подписать данные
			ASN1.ISO.PKCS.PKCS7.SignerInfo signerInfo = CMS.SignData(
				rand, privateKey, certificate, hashParameters, signParameters, 
                encapContentInfo, authAttributes, unauthAttributes
			); 
			// закодировать зашифрованные данные
			ASN1.ISO.PKCS.PKCS7.SignerInfos signerInfos = 
				new ASN1.ISO.PKCS.PKCS7.SignerInfos(
					new ASN1.ISO.PKCS.PKCS7.SignerInfo[] {signerInfo}
			);
			// закодировать структуру CMS
			ASN1.ISO.PKCS.PKCS7.SignedData signedData = 
				new ASN1.ISO.PKCS.PKCS7.SignedData(version, 
					digestAlgorithms, encapContentInfo, certificates, crls, signerInfos
			); 
			// закодировать данные
			ASN1.ISO.PKCS.ContentInfo contentInfo = new ASN1.ISO.PKCS.ContentInfo(
				new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS7.OID.signedData), signedData
			); 
			// вернуть созданный контейнер
			return new ASN1.ISO.PKCS.PKCS12.PFX(new ASN1.Integer(3), contentInfo, null); 
		}
		///////////////////////////////////////////////////////////////////////
		// Создать контейнер PKCS12 с вычисленной имитовставкой
		///////////////////////////////////////////////////////////////////////
		public static ASN1.ISO.PKCS.PKCS12.PFX CreateAuthenticatedContainer(
			Factory factory, ASN1.ISO.PKCS.PKCS12.AuthenticatedSafe authenticatedSafe, 
			ASN1.ISO.AlgorithmIdentifier hashParameters, byte[] salt, int iterations, string password)
		{
			// закодировать данные
			byte[] encoded = authenticatedSafe.Encoded;  

			// создать алгоритм хэширования 
			using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(null, hashParameters))
            { 
			    // при ошибке выбросить исключение
			    if (hashAlgorithm == null) throw new NotSupportedException(); 

			    // создать алгоритм вычисления имитовставки
			    using (Mac macAlgorithm = new PBE.PBMACP12(hashAlgorithm, salt, iterations)) 
                {
			        // закодировать пароль
			        using (ISecretKey encodedPassword = SecretKey.FromPassword(password, Encoding.UTF8))
                    { 
			            // вычислить имитовставку от данных
			            ASN1.OctetString mac = new ASN1.OctetString(macAlgorithm.MacData(
				            encodedPassword, encoded, 0, encoded.Length
			            )); 
			            // закодировать данные
			            ASN1.ISO.PKCS.ContentInfo contentInfo = new ASN1.ISO.PKCS.ContentInfo(
				            new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS7.OID.data), 
                            new ASN1.OctetString(encoded)
			            ); 
			            // закодировать имитовставку от данных
			            ASN1.ISO.PKCS.DigestInfo digestInfo = 
				            new ASN1.ISO.PKCS.DigestInfo(hashParameters, mac); 

			            // закодировать информацию об имитовставке
			            ASN1.ISO.PKCS.PKCS12.MacData macData = new ASN1.ISO.PKCS.PKCS12.MacData(
				            digestInfo, new ASN1.OctetString(salt), new ASN1.Integer(iterations)
			            ); 
			            // вернуть созданную структуру
			            return new ASN1.ISO.PKCS.PKCS12.PFX(new ASN1.Integer(3), contentInfo, macData); 
                    }
                }
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Проверить имитовставку контейнера
		///////////////////////////////////////////////////////////////////////
		public static void CheckAuthenticatedContainer(Factory factory, 
			ASN1.ISO.PKCS.PKCS12.PFX content, string password)
		{
			// получить закодированные данные
			byte[] encoded = content.GetAuthSafeContent().Encoded;

			// получить закодированную имитовставку
			ASN1.ISO.PKCS.PKCS12.MacData macData = content.MacData; 

            // получить salt-значение
            byte[] salt = macData.MacSalt.Value; 

		    // получить число итераций
		    int iterations = macData.Iterations.Value.IntValue; 

            // получить имитовставку
            byte[] mac = macData.Mac.Digest.Value; 

			// создать алгоритм хэширования 
			using (Hash hashAlgorithm = factory.CreateAlgorithm<Hash>(null, macData.Mac.DigestAlgorithm))
            { 
			    // при ошибке выбросить исключение
			    if (hashAlgorithm == null) throw new NotSupportedException(); 

			    // создать алгоритм вычисления имитовставки
			    using (Mac macAlgorithm = new PBE.PBMACP12(hashAlgorithm, salt, iterations))
                {
			        // закодировать пароль
			        using (ISecretKey encodedPassword = SecretKey.FromPassword(password, Encoding.UTF8))
                    { 
			            // вычислить имитовставку от данных
			            byte[] check = macAlgorithm.MacData(encodedPassword, encoded, 0, encoded.Length); 

			            // извлечь имитовставку для сравнения
			            if (!Arrays.Equals(check, mac)) 
                        {
                            // создать алгоритм вычисления имитовставки
                            using (Mac macAlgorithm2 = new PBE.PBMACTC26(hashAlgorithm, salt, iterations))
                            {
                                // вычислить имитовставку от данных
                                check = macAlgorithm2.MacData(encodedPassword, encoded, 0, encoded.Length);
                            }
                        }
                        // проверить совпадение имитовставок
                        if (!Arrays.Equals(check, mac)) throw new InvalidCredentialException();
                    }
                }
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Зашифровать элемент 
		///////////////////////////////////////////////////////////////////////
		internal static ASN1.ISO.PKCS.PKCS12.SafeBag Encrypt(PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag> safeBag)
		{
			// проверить наличие шифрования
			if (safeBag.Encryptor == null) return safeBag.Content; 

			// в зависимости от типа
			if (safeBag.Content.BagId.Value == ASN1.ISO.PKCS.PKCS12.OID.bt_key)
			{
				// раскодировать тип данных
				ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo keyInfo = 
					new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(safeBag.Content.BagValue);

				// зашифровать данные
				ASN1.IEncodable encodable = ASN1.Encodable.Decode(
                    safeBag.Encryptor.Encrypt(keyInfo.Encoded)
                ); 
				// преобразовать тип данных
				ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo encryptedKey = 
					new ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo(encodable);

				// вернуть зашифрованное представление
				return new ASN1.ISO.PKCS.PKCS12.SafeBag(
					new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_shroudedKey), 
                    encryptedKey, safeBag.Content.BagAttributes);
			}
			else return safeBag.Content; 
		}
		///////////////////////////////////////////////////////////////////////
		// Расшифровать элемент
		///////////////////////////////////////////////////////////////////////
		internal static PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag> Decrypt(
            ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, PfxDecryptor decryptor)
		{
			// для незашифрованного элемента
			if (safeBag.BagId.Value != ASN1.ISO.PKCS.PKCS12.OID.bt_shroudedKey)
			{
			    // вернуть исходное содержимое
			    return new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>(safeBag, null);
            }
			// расшифровать данные
			PfxData<byte[]> decrypted = decryptor.Decrypt(safeBag.BagValue.Encoded,
                typeof(ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo)
            );
			// преобразовать тип данных 
			ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo keyInfo = 
				new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(
                    ASN1.Encodable.Decode(decrypted.Content)
            );
			// сформировать элемент контейнера
			safeBag = new ASN1.ISO.PKCS.PKCS12.SafeBag(
    			new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_key), 
                keyInfo, safeBag.BagAttributes
            );
            // вернуть элемент контейнера
            return new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>(
                safeBag, decrypted.Encryptor
            ); 
		}
	}
}
