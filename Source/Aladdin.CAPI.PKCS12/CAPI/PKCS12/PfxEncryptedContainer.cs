using System;
using System.IO;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Зашифрованный на пароле контейнер PKCS12
	///////////////////////////////////////////////////////////////////////////
	public abstract class PfxEncryptedContainer : PfxContainer
	{
        // фабрика алгоритмов и ключ шифрования контейнера
        private Factory factory; private ISecretKey key;	

		// конструктор
		protected PfxEncryptedContainer(ASN1.ISO.PKCS.PKCS12.PFX content, 
            Factory factory, IRand rand) : base(content, rand)
        { 
            // сохранить переданные параметры
            this.factory = RefObject.AddRef(factory); key = null; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
		    RefObject.Release(key); RefObject.Release(factory); base.OnDispose();
        }
        // фабрика алгоритмов
        public Factory Factory { get { return factory; }} 
        // ключ шифрования контейнера
        public ISecretKey EncryptionKey { get { return key; }}

		// указать пароль
        public void SetEncryptionKey(ISecretKey key)
		{
            // освободить выделенные ресурсы
            RefObject.Release(this.key); this.key = null; 

			// расшифровать зашифрованные элементы
			this.key = RefObject.AddRef(key); base.Decrypt(this); 
		}
        // изменить пароль
        public void ChangeEncryptionKey(ISecretKey key)
		{
            // проверить наличие ключа
            if (this.key == null) throw new UnauthorizedAccessException(); 

			// указать новый пароль
			ISecretKey oldKey = this.key; this.key = RefObject.AddRef(key); 

            // обработать изменение данных
            try { Change(); RefObject.Release(oldKey); } 
            
            // восстановить пароль при возникновении ошибки
            catch { RefObject.Release(key); this.key = oldKey; throw; }
		}
		// зашифровать элемент
		public override byte[] Encrypt(PBE.PBECulture culture, byte[] data, Type encryptionType)
		{
			// проверить наличие параметров
			if (culture == null) throw new InvalidOperationException();

			// проверить наличие ключа
			if (key == null) throw new UnauthorizedAccessException();

			// в зависимости от типа
			if (encryptionType == typeof(ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo))
			{
                // указать способ шифрования
                PfxEncryptor encryptor = new PfxEncryptor.PrivateKeyCipherWrap(
                    this, culture.CipherAlgorithm(Rand)
                ); 
                // зашифровать личный ключ
                return encryptor.Encrypt(data); 
			}
			else if (encryptionType == null || 
                     encryptionType == typeof(ASN1.ISO.PKCS.PKCS7.EnvelopedData) || 
                     encryptionType == typeof(ASN1.ISO.PKCS.PKCS7.EncryptedData))
            {
                // указать способ шифрования
                PfxEncryptor encryptor = new PfxEncryptor.CultureWrap(
                    this, culture, ASN1.ISO.PKCS.PKCS7.OID.data, null 
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
			if (key == null) throw new UnauthorizedAccessException();

			// в зависимости от типа
			if (encryptionType == typeof(ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo))
			{
				// преобразовать тип данных
				ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = 
					new ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo(ASN1.Encodable.Decode(data)); 
                try { 
			        // указать функцию зашифрования
			        PfxEncryptor encryptor = new PfxEncryptor.PrivateKeyCipherWrap(
                        this, encryptedPrivateKeyInfo.EncryptionAlgorithm
                    ); 
				    // расшифровать данные
                    data = CMS.DecryptPrivateKey(factory, null, key, encryptedPrivateKeyInfo).Encoded; 

                    // вернуть расшифрованные данные
                    return new PfxData<byte[]>(data, encryptor); 
                }
                // обработать неожидаемое исключение
                catch (InvalidKeyException e) { throw new InvalidDataException(e.Message, e); }
			}
			// в зависимости от типа
			else if (encryptionType == typeof(ASN1.ISO.PKCS.PKCS7.EnvelopedData))
			{
				// преобразовать тип данных
				ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = 
					new ASN1.ISO.PKCS.PKCS7.EnvelopedData(ASN1.Encodable.Decode(data)); 

				// раскодировать структуру
				ASN1.ISO.PKCS.PKCS7.EncryptedContentInfo encryptedContentInfo = envelopedData.EncryptedContentInfo; 
					
				// раскодировать структуру
				ASN1.ISO.PKCS.PKCS7.RecipientInfos recipientInfos = envelopedData.RecipientInfos; 

				// раскодировать структуру
				ASN1.ISO.PKCS.PKCS7.PasswordRecipientInfo recipientInfo = 
					new ASN1.ISO.PKCS.PKCS7.PasswordRecipientInfo(recipientInfos[0]); 

                // получить параметры алгоритма шифрования
                ASN1.ISO.AlgorithmIdentifier cipherParameters = 
                    encryptedContentInfo.ContentEncryptionAlgorithm; 

                // создать алгоритм шифрования
                using (Cipher cipher = factory.CreateAlgorithm<Cipher>(null, cipherParameters))
                {
                    // при ошибке выбросить исключение
                    if (cipher == null) throw new NotSupportedException();
                    try {  
			            // расшифровать ключ шифрования данных по паролю
			            using (ISecretKey CEK = CMS.PasswordDecryptKey(
                            factory, null, key, recipientInfo, cipher.KeyFactory)) 
			            {
			                // указать функцию зашифрования
			                PfxEncryptor encryptor = new PfxEncryptor.PasswordWrap(this, 
                                encryptedContentInfo.ContentEncryptionAlgorithm, 
                                recipientInfo.KeyDerivationAlgorithm, 
                                recipientInfo.KeyEncryptionAlgorithm, 
                                encryptedContentInfo.ContentType.Value, envelopedData.UnprotectedAttrs
                            ); 
    				        // расшифровать данные
				            data = CMS.DecryptData(factory, null, CEK, 
                                encryptedContentInfo, envelopedData.UnprotectedAttrs).Content; 

                            // вернуть расшифрованные данные
                            return new PfxData<byte[]>(data, encryptor); 
                        }
                    }
                    // обработать неожидаемое исключение
                    catch (InvalidKeyException e) { throw new InvalidDataException(e.Message, e); }
                }
			}
			else if (encryptionType == typeof(ASN1.ISO.PKCS.PKCS7.EncryptedData)) 
			{
				// преобразовать тип данных
				ASN1.ISO.PKCS.PKCS7.EncryptedData encryptedData = 
					new ASN1.ISO.PKCS.PKCS7.EncryptedData(ASN1.Encodable.Decode(data)); 

				// извлечь зашифрованные данные
				ASN1.ISO.PKCS.PKCS7.EncryptedContentInfo encryptedContentInfo = encryptedData.EncryptedContentInfo; 

			    // указать функцию зашифрования
			    PfxEncryptor encryptor = new PfxEncryptor.CipherWrap(this, 
                    encryptedContentInfo.ContentEncryptionAlgorithm,
                    encryptedData.UnprotectedAttrs, encryptedContentInfo.ContentType.Value); 
                try { 
				    // расшифровать данные 
                    data = CMS.DecryptData(factory, null, key, encryptedData).Content;

                    // вернуть расшифрованные данные
                    return new PfxData<byte[]>(data, encryptor); 
                }
                // обработать неожидаемое исключение
                catch (InvalidKeyException e) { throw new InvalidDataException(e.Message, e); }
			}
			return null; 
		}
	}
}
