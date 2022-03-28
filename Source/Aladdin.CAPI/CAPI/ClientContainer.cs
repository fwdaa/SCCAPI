using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Контейнер
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class ClientContainer : RefObject, IClient
    {
        // криптографический провайдер и информация о контейнере
        private CryptoProvider provider; private SecurityInfo info;
        // способ выбора аутентификации
        private AuthenticationSelector selector;

        // конструктор
        public ClientContainer(CryptoProvider provider, 
            SecurityInfo info, AuthenticationSelector selector)
        {
            // сохранить переданные параметры
            this.provider = RefObject.AddRef(provider); this.info = info;
            
            // указать значение селектора по умолчанию
            this.selector = (selector != null) ? selector : new AuthenticationSelector("USER");
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(provider); base.OnDispose(); 
        }
        // криптографический провайдер
        public CryptoProvider Provider { get { return provider; }}

        // информация контейнера
        public SecurityInfo Info { get { return info; }}

        ///////////////////////////////////////////////////////////////////////
        // Уникальный идентификатор
        ///////////////////////////////////////////////////////////////////////
        public string GetUniqueID()
        {
            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
            {
                // получить уникальный идентификатор
                return container.GetUniqueID(); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Способ использования ключа
        ///////////////////////////////////////////////////////////////////////
        public KeyUsage GetKeyUsage(string keyOID)
        {
            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
            {
                // получить способ использования ключа
                return provider.GetKeyFactory(keyOID).GetKeyUsage(); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Генератор случайных данных
        ///////////////////////////////////////////////////////////////////////
        public IRand CreateRand()
        {
            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
            {
                // создать генератор случайных данных
                return selector.CreateRand(provider, container); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Открытые ключи контейнера
        ///////////////////////////////////////////////////////////////////////
        public IPublicKey GetPublicKey(byte[] keyID)
        {
            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
            {
                // получить открытый ключ из контейнера
                return container.GetPublicKey(keyID);
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Личные ключи контейнера
        ///////////////////////////////////////////////////////////////////////
        public byte[] GetPrivateKey(Certificate certificate, ASN1.ISO.Attributes attributes)
        {
    	    // открыть контейнер
		    using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
		    {
                // закодировать личный ключ
                return container.GetPrivateKey(certificate, attributes); 
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Сертификаты контейнера
        ///////////////////////////////////////////////////////////////////////
        public Certificate[] EnumerateAllCertificates() 
        { 
    	    // открыть контейнер
		    using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
		    {
                // перечислить сертификаты
                return container.EnumerateAllCertificates(); 
            }
        }
        public Certificate[] EnumerateCertificates() 
        { 
    	    // открыть контейнер
		    using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
		    {
                // перечислить сертификаты
                return container.EnumerateCertificates(); 
            }
        }
        public Certificate GetCertificate(byte[] keyID, bool useSelector)
        {
            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
            {
                // получить сертификат из контейнера
                return container.GetCertificate(keyID);
            }
        }
        public void SetCertificate(byte[] keyID, Certificate certificate)
        {
            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.ReadWrite))
            {
                // получить открытый ключ
                IPublicKey publicKey = container.GetPublicKey(keyID); 
        
                // проверить наличие ключа
                if (publicKey == null) throw new NotFoundException(); 

                // закодировать открытый ключ
                ASN1.ISO.PKIX.SubjectPublicKeyInfo keyInfo = publicKey.Encoded; 

                // проверить совпадение открытых ключей
                if (!certificate.PublicKeyInfo.Equals(keyInfo)) 
                {
                    // при ошибке выбросить исключение
                    throw new InvalidDataException(); 
                }
                // записать сертификат в контейнер
                container.SetCertificate(keyID, certificate);
            }
        }
        ///////////////////////////////////////////////////////////////////////
        // Ключевые пары контейнера
        ///////////////////////////////////////////////////////////////////////
        public ContainerKeyPair[] EnumerateKeyPairs()
        {
            // выделить память для пар ключей
            List<ContainerKeyPair> keyPairs = new List<ContainerKeyPair>();

            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
            {
                // для всех ключей контейнера
                foreach (byte[] id in container.GetKeyIDs())
                try {
                    // получить сертификат
                    Certificate certificate = container.GetCertificate(id); string keyOID = null;

                    // указать идентификатор ключа
                    if (certificate == null) keyOID = container.GetPublicKey(id).KeyOID;

                    // указать идентификатор ключа
                    else keyOID = certificate.PublicKeyInfo.Algorithm.Algorithm.Value;

                    // добавить пару ключей в список
                    keyPairs.Add(new ContainerKeyPair(info, id, keyOID, certificate));
                }
                // вернуть описание ключей
                catch {} return keyPairs.ToArray();
            }
        }
        public ContainerKeyPair GetKeyPair(Certificate certificate)
        {
            // определить идентификатор ключа
            string keyOID = certificate.PublicKeyInfo.Algorithm.Algorithm.Value; 

            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
            {
                // найти ключевую пару для сертификата
                byte[] keyID = container.GetKeyPair(certificate); 

                // проверить наличие ключевой пары
                if (keyID == null) return null; 

                // вернуть найденную ключевую пару
                return new ContainerKeyPair(info, keyID, keyOID, certificate); 
            }
        }
        public void DeleteKeyPair(byte[] keyID)
        {
            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Write))
            {
                // удалить ключевую пару контейнера
                container.DeleteKeyPair(keyID);
            }
        }
        ///////////////////////////////////////////////////////////////////////
		// Сгенерировать пару ключей
		///////////////////////////////////////////////////////////////////////
        public ContainerKeyPair GenerateKeyPair(IRand rand, IParametersFactory factory, 
            string keyOID, KeyUsage keyUsage, KeyFlags keyFlags)
		{
            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.ReadWrite)) 
            { 
                // указать генератор случайных данных
                using (IRand rebindRand = selector.RebindRand(rand))
                { 
                    // выбрать параметры алгоритма
                    IParameters keyParameters = factory.GetParameters(rebindRand, keyOID, keyUsage); 

                    // сгенерировать ключи в контейнере
                    using (KeyPair keyPair = container.GenerateKeyPair(
                        rebindRand, null, keyOID, keyParameters, keyUsage, keyFlags)) 
                    { 
                        // закрыть контейнер
                        return new ContainerKeyPair(info, keyPair.KeyID, keyOID, null);
                    }
                }
            }
		}
		///////////////////////////////////////////////////////////////////////
		// Импортировать/экспортировать пару ключей
		///////////////////////////////////////////////////////////////////////
		public ContainerKeyPair ImportKeyPair(IRand rand, IPublicKey publicKey, 
            IPrivateKey privateKey, Certificate certificate, KeyUsage keyUsage, KeyFlags keyFlags)
        {
            // открыть исходный контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.ReadWrite))
            { 
                // указать генератор случайных данных
                using (IRand rebindRand = selector.RebindRand(rand))
                { 
  		            // импортировать ключи в контейнер
			        using (KeyPair keyPair = container.ImportKeyPair(rebindRand, publicKey, privateKey, keyUsage, keyFlags)) 
                    { 
                        // записать сертификат в контейнер
                        if (certificate != null) container.SetCertificate(keyPair.KeyID, certificate);
                            
                        // вернуть описание пары ключей контейнера
                        return new ContainerKeyPair(info, keyPair.KeyID, publicKey.KeyOID, certificate); 
                    }
                }
            }
        }
		public ContainerKeyPair ExportKeyPair(byte[] keyID, CryptoProvider providerTo, 
            SecurityInfo infoTo, IRand rand, KeyUsage keyUsage, KeyFlags keyFlags)
		{
            // открыть исходный контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
            { 
                // получить открытый ключ
                IPublicKey publicKey = container.GetPublicKey(keyID);

                // проверить наличие ключа
                if (publicKey == null) throw new NotFoundException();

                // получить сертификат
                Certificate certificate = container.GetCertificate(keyID);

                // получить личный ключ
                using (IPrivateKey privateKey = container.GetPrivateKey(keyID))
                {
                    // указать другой контейнер
                    using (ClientContainer containerTo = new ClientContainer(providerTo, infoTo, selector))
                    { 
                        // импортировать пару ключей
                        return containerTo.ImportKeyPair(rand, publicKey, privateKey, certificate, keyUsage, keyFlags); 
                    }
                }
            }
        }
		///////////////////////////////////////////////////////////////////////
		// Создать самоподписанный сертификат
		///////////////////////////////////////////////////////////////////////
        public Certificate CreateSelfSignedCertificate(IRand rand, 
            byte[] keyID, ASN1.IEncodable subject, ASN1.ISO.AlgorithmIdentifier signParameters,
            DateTime notBefore, DateTime notAfter, KeyUsage keyUsage, string[] extKeyUsages, 
            ASN1.ISO.PKIX.CE.BasicConstraints basicConstraints, 
            ASN1.ISO.PKIX.CE.CertificatePolicies policies, ASN1.ISO.PKIX.Extensions extensions)
        {
            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.ReadWrite)) 
            {
                // получить открытый ключ
                IPublicKey publicKey = container.GetPublicKey(keyID); 

                // проверить наличие ключа
                if (publicKey == null) throw new NotFoundException(); 

			    // получить личный ключ
			    using (IPrivateKey privateKey = container.GetPrivateKey(keyID)) 
                {
                    // указать генератор случайных данных
                    using (IRand rebindRand = selector.RebindRand(rand))
                    {
                        // создать самоподписанный сертификат
                        Certificate certificate = PKI.CreateSelfSignedCertificate(
                            rebindRand, subject, signParameters, publicKey, privateKey, 
                            notBefore, notAfter, keyUsage, extKeyUsages, 
                            basicConstraints, policies, extensions
                        ); 
                        // записать сертификат в контейнер
                        container.SetCertificate(keyID, certificate); return certificate; 
                    }
                }
            }
        }
		///////////////////////////////////////////////////////////////////////
		// Создать запрос на сертификат
		///////////////////////////////////////////////////////////////////////
		public CertificateRequest CreateCertificateRequest(
            IRand rand, byte[] keyID, ASN1.IEncodable subject, 
            ASN1.ISO.AlgorithmIdentifier signParameters, ASN1.ISO.PKIX.Extensions extensions)
		{
            // открыть контейнер
            using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
            {
                // получить открытый ключ
                IPublicKey publicKey = container.GetPublicKey(keyID); 

                // проверить наличие ключа
                if (publicKey == null) throw new NotFoundException(); 

        	    // получить личный ключ
			    using (IPrivateKey privateKey = container.GetPrivateKey(keyID)) 
                {
                    // указать генератор случайных данных
                    using (IRand rebindRand = selector.RebindRand(rand))
                    {
                        // сгенерировать запрос на сертификат
                        return PKI.CreateCertificationRequest(rebindRand, 
                            subject, signParameters, publicKey, privateKey, extensions
                        );
                    }
                }
			}
		}
        ///////////////////////////////////////////////////////////////////////
        // Выполнение криптографических операций
        ///////////////////////////////////////////////////////////////////////
        public byte[] EncryptData(IRand rand, Culture culture, 
            Certificate certificate, Certificate[] recipientCertificates, 
            CMSData data, ASN1.ISO.Attributes attributes)
        {
    	    // открыть контейнер
		    using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
		    {
                // указать генератор случайных данных
                using (IRand rebindRand = selector.RebindRand(rand))
                {
                    // зашифровать данные
                    return container.EncryptData(rebindRand, culture, 
                        certificate, recipientCertificates, data, attributes
                    ); 
                }
            }
        }
		public CMSData DecryptData(byte[] contentInfo)
        {
			// открыть контейнер
			using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
			{
                // расшифровать данные
                return container.DecryptData(contentInfo);
            }
        }
        public byte[] SignData(IRand rand, Culture culture, 
            Certificate certificate, CMSData data, 
            ASN1.ISO.Attributes authAttributes, ASN1.ISO.Attributes unauthAttributes)
        {
    	    // открыть контейнер
		    using (Container container = (Container)selector.OpenObject(
                provider, info.Scope, info.FullName, FileAccess.Read))
		    {
                // указать генератор случайных данных
                using (IRand rebindRand = selector.RebindRand(rand))
                {
                    // подписать данные
                    return container.SignData(rebindRand, culture, 
                        certificate, data, authAttributes, unauthAttributes
                    );
                }
            }
        }
    }
}
