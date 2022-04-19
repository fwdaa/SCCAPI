using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Пользователь ключей
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public sealed class Client : RefObject, IClient
    {
        // сертификаты и личные ключи клиента
        private Dictionary<Certificate, IPrivateKey> keyPairs; 
        // сертификаты и цепочки сертификатов
        private Dictionary<Certificate, Certificate[]> certChains; 

		// раскодировать контейнер в памяти
		public Client(Software.CryptoProvider provider, byte[] encodedStore, string password)
		{
            // выделить списки для сертификатов и личных ключей
            keyPairs = new Dictionary<Certificate, IPrivateKey>(); 

            // выделить память для цепочек сертификатов
            certChains = new Dictionary<Certificate, Certificate[]>(); 

            // указать поток для обработки
            using (MemoryStream stream = new MemoryStream(encodedStore))
            { 
                // открыть хранилище контейнеров
                using (Container container = provider.OpenMemoryContainer(stream, FileAccess.Read, password))
                {
                    // для всех ключей
                    foreach (byte[] keyID in container.GetKeyIDs())
                    { 
                        // получить сертификат для ключа
                        Certificate certificate = container.GetCertificate(keyID); 

                        // при отсутствии сертификата в списке
                        if (certificate != null && !keyPairs.ContainsKey(certificate))
                        try { 
                            // получить цепь сертификатов
                            Certificate[] certificateChain = container.GetCertificateChain(certificate); 

                            // добавить личный ключ в список
                            keyPairs.Add(certificate, container.GetPrivateKey(keyID)); 

                            // добавить цепочку сертификатов
                            certChains.Add(certificate, certificateChain); 
                        }
                        // обработать возможную ошибку
                        catch (NotFoundException) {}
                    }
                }
            }
            // проверить наличие ключей
            if (keyPairs.Count == 0) throw new NotFoundException();
        }
	    // конструктор
	    public Client(IPrivateKey privateKey, Certificate[] certificateChain)
        {
            // выделить списки для сертификатов и личных ключей
            keyPairs = new Dictionary<Certificate, IPrivateKey>(); 
        
            // добавить пару ключей в список
            keyPairs.Add(certificateChain[0], RefObject.AddRef(privateKey)); 

            // выделить память для цепочек сертификатов
            certChains = new Dictionary<Certificate, Certificate[]>(); 

            // добавить цепочку сертификатов
            certChains.Add(certificateChain[0], certificateChain); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // для всех ключей
            foreach (IPrivateKey privateKey in keyPairs.Values) 
            {
                // освободить ключ
                RefObject.Release(privateKey);
            }
            // вызвать базовую функцию
            base.OnDispose(); 
        }
        // уникальный идентификатор
        public string GetUniqueID() { return null; }

        // сертификаты пользователя
        public Certificate[] EnumerateCertificates() 
        { 
            // создать список сертификатов
            Certificate[] certificates = new Certificate[keyPairs.Count]; 

            // скопировать список сертификатов
            keyPairs.Keys.CopyTo(certificates, 0); return certificates; 
        }
        // личный ключ для шифрования
        public byte[] GetPrivateKey(Certificate certificate, ASN1.ISO.Attributes attributes)
        {
            // проверить наличие ключевой пары
            if (!keyPairs.ContainsKey(certificate)) return null;

            // закодировать личный ключ
            return keyPairs[certificate].Encode(attributes).Encoded; 
        }
        // зашифровать данные
        public byte[] EncryptData(IRand rand, Culture culture, 
            Certificate certificate, Certificate[] recipientCertificates, 
            CMSData data, ASN1.ISO.Attributes attributes)
        {
            // проверить наличие ключевой пары
            if (!keyPairs.ContainsKey(certificate)) throw new NotFoundException(); 

            // указать используемый личный ключ
            IPrivateKey privateKey = keyPairs[certificate]; 

            // найти цепочку сертификатов
            Certificate[] certificateChain = certChains[certificate]; 

            // зашифровать данные
            ASN1.ISO.PKCS.ContentInfo contentInfo = Culture.KeyxEncryptData(
                culture, rand, privateKey, certificateChain, 
                recipientCertificates, null, data, attributes
            ); 
            // вернуть зашифрованные данные
            return contentInfo.Encoded; 
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
        
            // найти подходящий для расшифрования сертификат
            Certificate certificate = CMS.FindCertificate(keyPairs.Keys, envelopedData); 

            // проверить наличие сертификата
            if (certificate == null) throw new NotFoundException();

            // расшифровать данные
            return CMS.KeyxDecryptData(keyPairs[certificate], certificate, null, envelopedData); 
        }
        // подписать данные
        public byte[] SignData(IRand rand, Culture culture, 
            Certificate certificate, CMSData data, 
            ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes)
        {
            // проверить наличие ключевой пары
            if (!keyPairs.ContainsKey(certificate)) throw new NotFoundException(); 

            // найти подходящий личный ключ
            IPrivateKey privateKey = keyPairs[certificate]; 

            // найти цепочку сертификатов
            Certificate[] certificateChain = certChains[certificate]; 

            // подписать данные
            ASN1.ISO.PKCS.ContentInfo contentInfo = Culture.SignData(
                culture, rand, privateKey, certificateChain, 
                data, authAttributes, unauthAttributes
            ); 
            // вернуть подписанные данные
            return contentInfo.Encoded; 
        }
    }
}
