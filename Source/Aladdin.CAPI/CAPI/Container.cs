using System;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический контейнер 
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class Container : SecurityObject, IClient
	{
        // конструктор
        public Container(ContainerStore store, object name) : base(store) { this.name = name; }
            
        // провайдер контейнера
        public new CryptoProvider Provider { get { return Store.Provider; }}
        // хранилище контейнера
        public new ContainerStore Store { get { return (ContainerStore)base.Store; }}
        // имя контейнера
        public override sealed object Name { get { return name; }} private object name; 

        // уникальный идентификатор
        public virtual string GetUniqueID() 
        {
            // уникальный идентификатор
            return String.Format("{0}\\{1}", Store.GetUniqueID(), Name); 
        }
		// получить идентификаторы ключей
		public abstract byte[][] GetKeyIDs(); 

		// получить идентификаторы ключей
        public virtual byte[][] GetKeyIDs(ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo)
        {
            // создать список идентификаторов
            List<byte[]> keyIDs = new List<byte[]>(); 

            // для всех ключей
            foreach (byte[] keyID in GetKeyIDs())
            {
                // получить сертификат
                Certificate certificate = GetCertificate(keyID); 
                
                // проверить наличие сертификата
                if (certificate == null) continue; 

                // проверить совпадение открытых ключей
                if (certificate.PublicKeyInfo.Equals(publicKeyInfo)) keyIDs.Add(keyID); 
            }
            // вернуть список идентификаторов
            return keyIDs.ToArray(); 
        } 
	    // получить открытый/личный ключ
	    public abstract IPublicKey  GetPublicKey (byte[] keyID); 
		public abstract IPrivateKey GetPrivateKey(byte[] keyID);
 
        // личный ключ пользователя
        public byte[] GetPrivateKey(Certificate certificate, ASN1.ISO.Attributes attributes)
        {
            // найти соответствующую пару ключей
            byte[] keyID = GetKeyPair(certificate); if (keyID == null) return null;
            try {  
                // получить личный ключ
                using (IPrivateKey privateKey = GetPrivateKey(keyID))  
                {
                    // закодировать личный ключ
                    return privateKey.Encode(attributes).Encoded; 
                }
            }
            // обработать возможное исключение
            catch (NotFoundException) { return null; }
        }
        // все сертификаты контейнера
        public virtual Certificate[] EnumerateAllCertificates()
        {
            // вернуть сертификаты пользователя
            return EnumerateCertificates(); 
        }
        // сертификаты пользователя
        public Certificate[] EnumerateCertificates()
        {
            // создать список сертификатов пользователя
            List<Certificate> certificates = new List<Certificate>(); 

            // для всех ключей
            foreach (byte[] keyID in GetKeyIDs())
            { 
                // получить сертификат для ключа
                Certificate certificate = GetCertificate(keyID); 

                // при отсутствии сертификата в списке
                if (certificate != null && !certificates.Contains(certificate))
                { 
                    // добавить сертификат в список
                    certificates.Add(certificate); 
                }
            }
            // вернуть список сертификатов
            return certificates.ToArray(); 
        }
		// получить сертификат открытого ключа
		public abstract Certificate GetCertificate(byte[] keyID); 

		// сохранить сертификат открытого ключа
		public abstract void SetCertificate(byte[] keyID, Certificate certificate); 

        // найти пару ключей
        public byte[] GetKeyPair(Certificate certificate)
        {
            // для всех ключей
            foreach (byte[] keyID in GetKeyIDs())
            {
                // получить сертификат для ключа
                Certificate cert = GetCertificate(keyID);

                // проверить совпадение сертификатов
                if (cert != null && cert.Equals(certificate)) return keyID; 
            }
            return null; 
        }
        // сгенерировать пару ключей
        public KeyPair GenerateKeyPair(IRand rand, byte[] keyID, string keyOID, 
            IParameters parameters, KeyUsage keyUsage, KeyFlags keyFlags)
        {
		    // получить фабрику кодирования ключей
		    KeyFactory keyFactory = Provider.GetKeyFactory(keyOID);
        
		    // проверить наличие фабрики
		    if (keyFactory == null) throw new NotSupportedException();

            // получить алгоритм генерации ключей
            using (KeyPairGenerator generator = Provider.CreateGenerator(
                this, keyOID, parameters, rand))
            {  
                // проверить наличие алгоритма
	            if (generator == null) throw new NotSupportedException();

	            // сгенерировать ключи алгоритма
	            return generator.Generate(keyID, keyOID, keyUsage, keyFlags);
            }
        }
        // импортировать пару ключей
		public virtual KeyPair ImportKeyPair(IRand rand, IPublicKey publicKey, 
            IPrivateKey privateKey, KeyUsage keyUsage, KeyFlags keyFlags)
		{
            // указать пару ключей
            using (KeyPair keyPair = new KeyPair(publicKey, privateKey, null))
            { 
			    // импортировать ключи в контейнер
			    byte[] keyID = SetKeyPair(rand, keyPair, keyUsage, keyFlags); 

		        // получить личный ключ
		        using (privateKey = GetPrivateKey(keyID))
                { 
                    // вернуть импортированную пару ключей
                    return new KeyPair(GetPublicKey(keyID), privateKey, keyID); 
                }
            }
		}
		// сохранить пару ключей
		public abstract byte[] SetKeyPair(IRand rand, 
            KeyPair keyPair, KeyUsage keyUsage, KeyFlags keyFlags 
        ); 
		// удалить пару ключей
		public abstract void DeleteKeyPair(byte[] keyID); 

	    // удалить все ключи
        public virtual void DeleteKeys() 
        {
            // удалить все ключевые пары
            foreach (byte[] keyID in GetKeyIDs()) DeleteKeyPair(keyID);
        }
        // зашифровать данные
        public byte[] EncryptData(IRand rand, Certificate certificate, 
            Certificate[] recipientCertificates, 
            CMSData data, ASN1.ISO.Attributes attributes)
        {
            // указать идентификатор ключа
            string keyOID = certificate.PublicKeyInfo.Algorithm.Algorithm.Value; 
            
            // найти соответствующую пару ключей
            byte[] keyID = GetKeyPair(certificate); 
            
            // проверить наличие пары ключей
            if (keyID == null) throw new NotFoundException(); 

            // получить личный ключ
            using (IPrivateKey privateKey = GetPrivateKey(keyID))  
            {
                // получить алгоритмы по умолчанию
                Culture culture = privateKey.Factory.GetCulture(privateKey.Scope, keyOID); 
            
                // проверить наличие алгоритмов
                if (culture == null) throw new NotSupportedException(); 
            
                // зашифровать данные
                ASN1.ISO.PKCS.ContentInfo contentInfo = Culture.KeyxEncryptData(
                    culture, rand, privateKey, certificate, 
                    recipientCertificates, null, data, attributes
                ); 
                // вернуть зашифрованные данные
                return contentInfo.Encoded; 
            }
        }
		// расшифровать данные на личном ключе
		public CMSData DecryptData(byte[] data)
        {
    	    // интерпретировать данные в формате ContentInfo
		    ASN1.ISO.PKCS.ContentInfo contentInfo = 
                new ASN1.ISO.PKCS.ContentInfo(ASN1.Encodable.Decode(data));

            // проверить тип данных
		    if (contentInfo.ContentType.Value != ASN1.ISO.PKCS.PKCS7.OID.envelopedData) 
            {
                // при ошибке выбросить исключение
                throw new InvalidDataException(); 
            }
		    // раскодировать данные
		    ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = 
                new ASN1.ISO.PKCS.PKCS7.EnvelopedData(contentInfo.Inner); 
        
            // создать список сертификатов пользователя
            Dictionary<Certificate, Byte[]> certificates = new Dictionary<Certificate, Byte[]>(); 

            // для всех ключей
            foreach (byte[] keyID in GetKeyIDs())
            { 
                // получить сертификат для ключа
                Certificate cert = GetCertificate(keyID); 

                // при отсутствии сертификата в списке
                if (cert != null && !certificates.ContainsKey(cert))
                { 
                    // добавить сертификат в список
                    certificates.Add(cert, keyID); 
                }
            }
            // найти подходящий для расшифрования сертификат
            Certificate certificate = CMS.FindCertificate(certificates.Keys, envelopedData); 

            // проверить наличие сертификата
            if (certificate == null) throw new NotFoundException();

            // получить личный ключ
            using (IPrivateKey privateKey = GetPrivateKey(certificates[certificate]))
            { 
                // расшифровать данные
                return CMS.KeyxDecryptData(privateKey, certificate, null, envelopedData);
            }
        }
        // подписать данные
        public byte[] SignData(IRand rand, Certificate certificate, CMSData data, 
            ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes)
        {
            // найти соответствующую пару ключей
            byte[] keyID = GetKeyPair(certificate); if (keyID == null) throw new NotFoundException();

            // указать идентификатор ключа
            string keyOID = certificate.PublicKeyInfo.Algorithm.Algorithm.Value; 
            
            // получить личный ключ
            using (IPrivateKey privateKey = GetPrivateKey(keyID))  
            {
                // получить алгоритмы по умолчанию
                Culture culture = privateKey.Factory.GetCulture(privateKey.Scope, keyOID); 
            
                // проверить наличие алгоритмов
                if (culture == null) throw new NotSupportedException(); 
            
                // подписать данные
                ASN1.ISO.PKCS.ContentInfo contentInfo = Culture.SignData(
                    culture, rand, privateKey, certificate, 
                    data, authAttributes, unauthAttributes
                ); 
                // вернуть подписанные данные
                return contentInfo.Encoded; 
            }
        }
		// установить признак использования по умолчанию
		public virtual void SetDefaultStoreContainer() {} 
    }
}
