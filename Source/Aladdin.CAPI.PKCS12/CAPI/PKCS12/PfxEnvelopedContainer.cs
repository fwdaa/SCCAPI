using System;
using System.IO;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Зашифрованный на открытом ключе контейнер PKCS12
	///////////////////////////////////////////////////////////////////////////
	public abstract class PfxEnvelopedContainer : PfxContainer
	{
        // фабрика алгоритмов, открытый ключ и сертификат
		private IPrivateKey privateKey; private Certificate certificate;
        // алгоритмы по умолчанию
        private CAPI.Culture culture;

		// конструктор
		protected PfxEnvelopedContainer(ASN1.ISO.PKCS.PKCS12.PFX content, 
            IRand rand) : base(content, rand) 
        { 
            // инициализировать переменные
            this.privateKey = null; this.certificate = null; 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
		    RefObject.Release(privateKey); base.OnDispose();
        }
        // личный ключ и сертификат
        public IPrivateKey EnvelopePrivateKey  { get { return privateKey;  }} 
        public Certificate EnvelopeCertificate { get { return certificate; }}

        // установить ключи
		public void SetEnvelopeKeys(IPrivateKey privateKey, Certificate certificate, CAPI.Culture culture)
		{
            // освободить выделенные ресурсы
            RefObject.Release(this.privateKey); this.privateKey = null; 
            
			// сохранить переданные параметры
			this.privateKey = RefObject.AddRef(privateKey); 
            
			// расшифровать зашифрованные элементы
            this.certificate = certificate; this.culture = culture; base.Decrypt(this); 
		}
        // переустановить ключи
		public void ChangeEnvelopeKeys(IPrivateKey privateKey, Certificate certificate)
		{
			// проверить наличие сертификата
			if (certificate == null || privateKey == null) throw new UnauthorizedAccessException();

			// сохранить старые ключи
			IPrivateKey oldPrivateKey = this.privateKey; Certificate oldCertificate = this.certificate; 

            // указать новые ключи
            this.privateKey = RefObject.AddRef(privateKey); this.certificate = certificate; 

            // обработать изменение данных
            try { Change(); RefObject.Release(oldPrivateKey); } catch { RefObject.Release(privateKey); 

                // восстановить ключи
                this.privateKey = oldPrivateKey; this.certificate = oldCertificate; throw; 
            }
        }
		// зашифровать элемент
        public override byte[] Encrypt(PBE.PBECulture cultureV, byte[] data, Type encryptionType)
		{
			// указать тип по умолчанию
			if (encryptionType == null) encryptionType = typeof(ASN1.ISO.PKCS.PKCS7.EnvelopedData); 

			// проверить наличие сертификата
			if (certificate == null || privateKey == null) throw new UnauthorizedAccessException();

            // определить идентификатор ключа
            String keyOID = certificate.PublicKeyInfo.Algorithm.Algorithm.Value; 
        
			// в зависимости от типа
			if (encryptionType == typeof(ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo))
			{
                // получить параметры алгоритма шифрования
                ASN1.ISO.AlgorithmIdentifier ciphermentParameters = culture.CiphermentAlgorithm(Rand); 
                
                // проверить указание параметров
                if (ciphermentParameters == null) throw new NotSupportedException();  

                // указать способ шифрования
                PfxEncryptor encryptor = new PfxEncryptor.PrivateKeyKeyxWrap(
                    this, ciphermentParameters
                ); 
                // зашифровать личный ключ
                return encryptor.Encrypt(data); 
            }
			else if (encryptionType == typeof(ASN1.ISO.PKCS.PKCS7.EnvelopedData))
			{
                // получить параметры алгоритма шифрования
                ASN1.ISO.AlgorithmIdentifier cipherParameters = culture.CipherAlgorithm(Rand); 
                
                // проверить указание параметров
                if (cipherParameters == null) throw new NotSupportedException();  
                
                // получить параметры шифрования
                ASN1.ISO.AlgorithmIdentifier keyxParameters = culture.KeyxParameters(
                    privateKey.Factory, privateKey.Scope, Rand, certificate.KeyUsage
                ); 
                // проверить указание параметров
                if (keyxParameters == null) throw new NotSupportedException();

                // указать способ шифрования
                PfxEncryptor encryptor = new PfxEncryptor.KeyxWrap(
                    this, cipherParameters, keyxParameters, 
                    ASN1.ISO.PKCS.PKCS7.OID.data, null
                ); 
                // зашифровать данные
                 return encryptor.Encrypt(data); 
            }
			return null; 
		}
		// расшифровать элемент
        public override PfxData<byte[]> Decrypt(byte[] data, Type encryptionType)
		{
			// проверить наличие ключа
			if (privateKey == null || certificate == null) throw new UnauthorizedAccessException();

			// в зависимости от типа
			if (encryptionType == typeof(ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo))
			{
				// преобразовать тип данных
				ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = 
					new ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo(ASN1.Encodable.Decode(data)); 

			    // указать функцию зашифрования
			    PfxEncryptor encryptor = new PfxEncryptor.PrivateKeyKeyxWrap(
                    this, encryptedPrivateKeyInfo.EncryptionAlgorithm
                ); 
				// расшифровать данные
				data = CMS.DecryptPrivateKey(privateKey, encryptedPrivateKeyInfo).Encoded;  

                // вернуть расшифрованные данные
                return new PfxData<byte[]>(data, encryptor); 
			}
			// в зависимости от типа
			else if (encryptionType == typeof(ASN1.ISO.PKCS.PKCS7.EnvelopedData))
			{
				// раскодировать элемент
				ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = 
					new ASN1.ISO.PKCS.PKCS7.EnvelopedData(ASN1.Encodable.Decode(data)); 

				// раскодировать структуру
				ASN1.ISO.PKCS.PKCS7.EncryptedContentInfo encryptedContentInfo = envelopedData.EncryptedContentInfo; 

				// раскодировать структуру
				ASN1.ISO.PKCS.PKCS7.RecipientInfos recipientInfos = envelopedData.RecipientInfos; 

				// раскодировать структуру
				ASN1.ISO.PKCS.PKCS7.KeyTransRecipientInfo recipientInfo = 
					new ASN1.ISO.PKCS.PKCS7.KeyTransRecipientInfo(recipientInfos[0]); 
					
				// раскодировать параметры шифрования
				ASN1.ISO.AlgorithmIdentifier cipherParameters = encryptedContentInfo.ContentEncryptionAlgorithm;

                // создать алгоритм шифрования
                using (Cipher cipher = privateKey.Factory.CreateAlgorithm<Cipher>(
                    privateKey.Scope, cipherParameters))
                {
                    // при ошибке выбросить исключение
                    if (cipher == null) throw new NotSupportedException();
                
                    // расшифровать ключ шифрования данных
                    using (ISecretKey CEK = CMS.TransportDecryptKey(privateKey, recipientInfo, cipher.KeyFactory))
                    {
			            // указать функцию зашифрования
			            PfxEncryptor encryptor = new PfxEncryptor.KeyxWrap(this, 
                            encryptedContentInfo.ContentEncryptionAlgorithm, 
                            recipientInfo.KeyEncryptionAlgorithm, 
                            encryptedContentInfo.ContentType.Value, envelopedData.UnprotectedAttrs
                        ); 
                        try {
                            // расшифровать данные
                            data = CMS.DecryptData(privateKey.Factory, privateKey.Scope, 
                                CEK, envelopedData.EncryptedContentInfo, envelopedData.UnprotectedAttrs).Content;

                            // вернуть расшифрованные данные
                            return new PfxData<byte[]>(data, encryptor); 
                        }
                        // обработать неожидаемое исключение
                        catch (InvalidKeyException e) { throw new InvalidDataException(e.Message, e); }
                    }
                }
			}
			return null; 
		}
	}
}
