using System;
using System.Collections.Generic;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Контейнер PKCS12
	///////////////////////////////////////////////////////////////////////////
	public sealed class Container : Software.Container
	{
        // парольная защита
        private PBE.IPBECultureFactory cultureFactory; 
	    // контейнер PKCS12
	    private PfxEncryptedContainer container; 

	    // открыть существующий контейнер
        public Container(PBE.IPBECultureFactory cultureFactory, IRand rand, 
            Software.ContainerStore store, Software.ContainerStream stream, 
            ASN1.ISO.PKCS.PKCS12.PFX pfx) : base(store, stream)
        { 
            // сохранить переданные параметры
            this.cultureFactory = cultureFactory; 

            // сохранить переданные параметры
            container = new PfxAuthenticatedEncryptedContainer(pfx, Provider, rand); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(container); base.OnDispose();
        }
	    // содержимое контейнера
	    public override byte[] Encoded { get { return container.Encoded.Encoded; }}
    
		///////////////////////////////////////////////////////////////////////////
		// Сервис аутентификации
		///////////////////////////////////////////////////////////////////////////
        public override AuthenticationService GetAuthenticationService(
            string user, Type authenticationType) 
        { 
            // проверить наличие парольной аутентификации
            if (typeof(Auth.PasswordCredentials).IsAssignableFrom(authenticationType)) 
            {
                // вернуть сервис аутентификации
                return new PasswordService(this, container); 
            }
            return null; 
        } 
        ///////////////////////////////////////////////////////////////////////////
        // Функции поиска по способу использования
        ///////////////////////////////////////////////////////////////////////////
        private byte[][] GetKeyIDs(KeyUsage keyUsage, bool set)
		{
			// создать список идентификаторов
			List<Byte[]> keyIDs = new List<Byte[]>(); 

			// указать функцию поиска запроса на сертификат
			PfxFilter reqFilter = new ContainerFilter.CertificationRequest(keyUsage, set, false); 
			
			// получить запросы на сертификат
			PfxContainerSafeBag[] reqBags = container.FindCertificationRequests(reqFilter); 

            // добавить все идентификаторы запросов на сертификат
            foreach (PfxContainerSafeBag bag in reqBags) keyIDs.Add(bag.ID);

			// указать функцию поиска сертификата
			PfxFilter certFilter = new ContainerFilter.Certificate(keyUsage, set, false);  

			// получить сертификаты открытого ключа
			PfxContainerSafeBag[] certBags = container.FindCertificates(certFilter); 

            // для всех идентификаторов сертификатов
            foreach (PfxContainerSafeBag bag in certBags)
            {
                // для всех присутствующих идентификаторов
                bool find = false; foreach (byte[] keyID in keyIDs)
                {
                    // проверить несовпадение идентификаторов
                    if (Arrays.Equals(bag.ID, keyID)) { find = true; break; }
                }
                // добавить неприсутствующий идентификатор
                if (!find) keyIDs.Add(bag.ID);
            }
			// проверить нахождение идентификаторов
			if (keyIDs.Count > 0 || set) return keyIDs.ToArray(); 
			
			// указать функцию поиска запроса на сертификат
			reqFilter = new ContainerFilter.CertificationRequest(keyUsage, set, true); 

			// получить запросы на сертификат
			reqBags = container.FindCertificationRequests(reqFilter); 

            // для всех идентификаторов запросов
            foreach (PfxContainerSafeBag bag in reqBags)
            {
                // для всех присутствующих идентификаторов
                bool find = false; foreach (byte[] keyID in keyIDs)
                {
                    // проверить несовпадение идентификаторов
                    if (Arrays.Equals(bag.ID, keyID)) { find = true; break; }
                }
                // добавить неприсутствующий идентификатор
                if (!find) keyIDs.Add(bag.ID);
            }
			// указать функцию поиска сертификата
			certFilter = new ContainerFilter.Certificate(keyUsage, set, true);

			// получить сертификаты открытого ключа
			certBags = container.FindCertificates(certFilter); 

            // для всех идентификаторов сертификатов
            foreach (PfxContainerSafeBag bag in certBags)
            {
                // для всех присутствующих идентификаторов
                bool find = false; foreach (byte[] keyID in keyIDs)
                {
                    // проверить несовпадение идентификаторов
                    if (Arrays.Equals(bag.ID, keyID)) { find = true; break; }
                }
                // добавить неприсутствующий идентификатор
                if (!find) keyIDs.Add(bag.ID);
            }
			return keyIDs.ToArray(); 
		}
		public override byte[][] GetKeyIDs()
		{
			// при полном зашифровании данных
			if (container.HasEncryptedItems && !container.HasDecryptedItems) 
			{
				// выполнить аутентификацию 
				if (!EnsureAuthenticate()) return new byte[0][];
			}
			// создать список идентификаторов
			List<Byte[]> keyIDs = new List<Byte[]>(); 

			// получить запросы на сертификат
			PfxContainerSafeBag[] reqBags = container.FindCertificationRequests(null); 

            // добавить все идентификаторы запросов на сертификат
            foreach (PfxContainerSafeBag bag in reqBags) keyIDs.Add(bag.ID);

			// получить сертификаты открытого ключа
			PfxContainerSafeBag[] certBags = container.FindCertificates(null); 

            // для всех идентификаторов сертификатов
            foreach (PfxContainerSafeBag bag in certBags)
            {
                // для всех присутствующих идентификаторов
                bool find = false; foreach (byte[] keyID in keyIDs)
                {
                    // проверить несовпадение идентификаторов
                    if (Arrays.Equals(bag.ID, keyID)) { find = true; break; }
                }
                // добавить неприсутствующий идентификатор
                if (!find) keyIDs.Add(bag.ID);
            }
			// получить сертификаты открытого ключа
			PfxContainerSafeBag[] keyBags = container.FindPrivateKeys(null); 

            // для всех идентификаторов сертификатов
            foreach (PfxContainerSafeBag bag in keyBags)
            {
                // для всех присутствующих идентификаторов
                bool find = false; foreach (byte[] keyID in keyIDs)
                {
                    // проверить несовпадение идентификаторов
                    if (Arrays.Equals(bag.ID, keyID)) { find = true; break; }
                }
                // добавить неприсутствующий идентификатор
                if (!find) keyIDs.Add(bag.ID);
            }
			return keyIDs.ToArray(); 
		}
		///////////////////////////////////////////////////////////////////////////
		// Функции поиска по открытому ключу
		///////////////////////////////////////////////////////////////////////////
		public override byte[][] GetKeyIDs(ASN1.ISO.PKIX.SubjectPublicKeyInfo keyInfo)
		{
			// при полном зашифровании данных
			if (container.HasEncryptedItems && !container.HasDecryptedItems) 
			{
                // выполнить аутентификацию 
                if (!EnsureAuthenticate()) return new byte[0][]; 
			}
			// создать список идентификаторов
			List<Byte[]> keyIDs = new List<Byte[]>(); 

			// указать функцию поиска сертификата
			PfxFilter filter = new ContainerFilter.CertificateInfo(keyInfo); 

			// получить сертификат открытого ключа
			PfxContainerSafeBag[] bags = container.FindCertificates(filter); 

            // добавить все идентификаторы сертификатов
            foreach (PfxContainerSafeBag bag in bags) keyIDs.Add(bag.ID);

			// при отсутствии сертификатов
			if (keyIDs.Count == 0) { filter = new ContainerFilter.CertificationRequestInfo(keyInfo); 
			
			    // получить запрос на сертификат
			    bags = container.FindCertificationRequests(filter);

                // добавить все идентификаторы сертификатов
                foreach (PfxContainerSafeBag bag in bags) keyIDs.Add(bag.ID);
            }
			// при отсутствии сертификатов
			if (keyIDs.Count == 0) { filter = new ContainerFilter.PrivateKeyInfo(Provider, keyInfo); 
			
			    // получить личный ключ
			    bags = container.FindPrivateKeys(filter);

                // добавить все идентификаторы сертификатов
                foreach (PfxContainerSafeBag bag in bags) keyIDs.Add(bag.ID);
            }
            return keyIDs.ToArray();
		}
		///////////////////////////////////////////////////////////////////////////
		// Найти сертификат
		///////////////////////////////////////////////////////////////////////////
        public override Certificate[] EnumerateAllCertificates()
        {
			// создать список сертификатов
			List<Certificate> certificates = new List<Certificate>(); 

			// при полном зашифровании данных
			if (container.HasEncryptedItems && !container.HasDecryptedItems) 
			{
                // выполнить аутентификацию
                if (!EnsureAuthenticate())  return certificates.ToArray(); 
            }
			// указать функцию поиска сертификатов
			PfxFilter certFilter = new ContainerFilter.Certificate(); 
			
			// получить сертификаты
			PfxContainerSafeBag[] certBags = container.FindCertificates(certFilter); 

            // для всех найденных сертификатов
            foreach (PfxContainerSafeBag bag in certBags)
            try {
	            // извлечь содержимое сертификата
	            ASN1.ISO.PKCS.PKCS12.CertBag certBag = 
                    new ASN1.ISO.PKCS.PKCS12.CertBag(bag.SafeBag.Decoded.BagValue); 

	            // раскодировать сертификат
	            certificates.Add(new Certificate(certBag.CertValue.Content)); 
            }
            // вернуть список сертификатов
            catch {} return certificates.ToArray();
        }
		public override Certificate GetCertificate(byte[] keyID)
		{
            PfxSafeBag item = null; 

			// при полном зашифровании данных
			if (container.HasEncryptedItems && !container.HasDecryptedItems) 
			{
                // выполнить аутентификацию
                if (!EnsureAuthenticate()) return null; 

                // найти элемент с сертификатом без аутентификации
                item = FindCertificateBag(keyID, false); 
            }
            else { 
                // найти элемент с сертификатом без аутентификации
                item = FindCertificateBag(keyID, false); 

                // найти элемент с сертификатом с аутентификацией
                if (item == null) item = FindCertificateBag(keyID, true); 
            }
            // проверить наличие сертификата
            if (item == null) return null; 

	        // извлечь содержимое сертификата
	        ASN1.ISO.PKCS.PKCS12.CertBag certBag = 
                new ASN1.ISO.PKCS.PKCS12.CertBag(item.Decoded.BagValue); 

	        // раскодировать сертификат
	        return new Certificate(certBag.CertValue.Content); 
        }
		private PfxSafeBag FindCertificateBag(byte[] keyID, bool authenticate)
		{
			// найти сертификат
			PfxSafeBag item = container.FindCertificate(keyID); if (item != null)
            {
                // проверить отсутствие шифрования
                if (item.Decoded != null) return item; 

                // при возможности аутентификации
                else if (authenticate)
                {
                    // выполнить аутентификацию
                    if (!EnsureAuthenticate()) return null; 

                    // вызвать функцию повторно
                    return FindCertificateBag(keyID, false); 
                }
            }
            // закодированный открытый ключ
            ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = null; 

		    // найти запрос на сертификат
		    if (publicKeyInfo == null && (item = container.FindCertificationRequest(keyID)) != null)
            {
                // для незашифрованного элемента
                if (item.Decoded != null)
                {
		            // извлечь содержимое запроса на сертификат 
		            ASN1.ISO.PKCS.PKCS12.SecretBag secretBag = 
			            new ASN1.ISO.PKCS.PKCS12.SecretBag(item.Decoded.BagValue); 

		            // раскодировать запрос на сертификат
		            publicKeyInfo = new CertificateRequest(secretBag.SecretValue.Content).PublicKeyInfo; 
                }
                else if (authenticate)
                {
                    // выполнить аутентификацию
                    if (!EnsureAuthenticate()) return null; 

                    // вызвать функцию повторно
                    return FindCertificateBag(keyID, false); 
                }
            }
		    // найти личный ключ
            if (publicKeyInfo == null && (item = container.FindPrivateKey(keyID)) != null)
            {
                // для незашифрованного элемента
                if (item.Decoded != null && item.Decoded.BagId.Value == ASN1.ISO.PKCS.PKCS12.OID.bt_key)
                {
			        // извлечь содержимое личного ключа
			        ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo = 
                        new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(item.Decoded.BagValue);

                    // pаскодировать пару ключей
                    using (KeyPair keyPair = Provider.DecodeKeyPair(privateKeyInfo))
                    {
                        // закодировать открытый ключ
                        publicKeyInfo = keyPair.PublicKey.Encoded;
                    } 
                }
                else if (authenticate)
                {
                    // выполнить аутентификацию
                    if (!EnsureAuthenticate()) return null; 

                    // вызвать функцию повторно
                    return FindCertificateBag(keyID, false); 
                }
            }
            // проверить наличие открытого ключа
            if (publicKeyInfo == null) return null; 
             
			// указать функцию поиска сертификата
			PfxFilter filter = new ContainerFilter.CertificateInfo(publicKeyInfo); 

			// получить сертификат открытого ключа
			PfxContainerSafeBag[] bags = container.FindCertificates(filter); 
            
            // вернуть элемент с сертификатом
            return (bags.Length != 0) ? bags[0].SafeBag : null; 
		}
		///////////////////////////////////////////////////////////////////////////
		// Найти запрос на сертификат
		///////////////////////////////////////////////////////////////////////////
		public CertificateRequest GetCertificateRequest(byte[] keyID)
		{
            PfxSafeBag item = null; 

			// при полном зашифровании данных
			if (container.HasEncryptedItems && !container.HasDecryptedItems) 
			{
                // выполнить аутентификацию 
                if (!EnsureAuthenticate()) return null; 

                // найти элемент с запросом на сертификат без аутентификацией
                item = FindCertificateRequestBag(keyID, true); 
            }
            else { 
                // найти элемент с запросом на сертификат без аутентификации
                item = FindCertificateRequestBag(keyID, false); 

                // найти элемент с запросом на сертификат без аутентификацией
                if (item == null) item = FindCertificateRequestBag(keyID, true); 
            }
            // проверить наличие сертификата
            if (item == null) return null; 

            // извлечь содержимое запроса на сертификат 
            ASN1.ISO.PKCS.PKCS12.SecretBag secretBag = 
	            new ASN1.ISO.PKCS.PKCS12.SecretBag(item.Decoded.BagValue); 

            // раскодировать запрос на сертификат
            return new CertificateRequest(secretBag.SecretValue.Content); 
        }
		private PfxSafeBag FindCertificateRequestBag(byte[] keyID, bool authenticate)
		{
		    // найти запрос на сертификат
			PfxSafeBag item = container.FindCertificationRequest(keyID); if (item != null)
            {
                // для незашифрованного элемента
                if (item.Decoded != null) return item; 

                // при возможности аутентификации
                else if (authenticate)
                {
                    // выполнить аутентификацию
                    if (!EnsureAuthenticate()) return null; 

                    // вызвать функцию повторно
                    return FindCertificateRequestBag(keyID, false); 
                }
            }
            // закодированный открытый ключ
            ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = null; 

		    // найти сертификат
		    if (publicKeyInfo == null && (item = container.FindCertificate(keyID)) != null)
            {
                // для незашифрованного элемента
                if (item.Decoded != null)
                {
	                // извлечь содержимое сертификата
	                ASN1.ISO.PKCS.PKCS12.CertBag certBag = 
                        new ASN1.ISO.PKCS.PKCS12.CertBag(item.Decoded.BagValue); 

	                // раскодировать сертификат
	                publicKeyInfo = new Certificate(certBag.CertValue.Content).PublicKeyInfo; 
                }
                else if (authenticate)
                {
                    // выполнить аутентификацию
                    if (!EnsureAuthenticate()) return null; 

                    // вызвать функцию повторно
                    return FindCertificateRequestBag(keyID, false); 
                }
            }
		    // найти личный ключ
            if (publicKeyInfo == null && (item = container.FindPrivateKey(keyID)) != null)
            {
                // для незашифрованного элемента
                if (item.Decoded != null &&  item.Decoded.BagId.Value == ASN1.ISO.PKCS.PKCS12.OID.bt_key)
                {
			        // извлечь содержимое личного ключа
			        ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo = 
                        new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(item.Decoded.BagValue);

                    // pаскодировать пару ключей
                    using (KeyPair keyPair = Provider.DecodeKeyPair(privateKeyInfo))
                    {
                        // закодировать открытый ключ
                        publicKeyInfo = keyPair.PublicKey.Encoded;
                    } 
                }
                else if (authenticate)
                {
                    // выполнить аутентификацию
                    if (!EnsureAuthenticate()) return null; 

                    // вызвать функцию повторно
                    return FindCertificateRequestBag(keyID, false); 
                }
            }
            // проверить наличие открытого ключа
            if (publicKeyInfo == null) return null; 
             
			// указать функцию поиска запроса на сертификат
			PfxFilter filter = new ContainerFilter.CertificationRequestInfo(publicKeyInfo); 

			// получить запрос на сертификат открытого ключа
			PfxContainerSafeBag[] bags = container.FindCertificates(filter); 
            
            // вернуть элемент с запросом на сертификат
            return (bags.Length != 0) ? bags[0].SafeBag : null; 
		}
		///////////////////////////////////////////////////////////////////////////
		// Найти открытый ключ
		///////////////////////////////////////////////////////////////////////////
		public override IPublicKey GetPublicKey(byte[] keyID)
		{
            ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = null; 

			// при полном зашифровании данных
			if (container.HasEncryptedItems && !container.HasDecryptedItems) 
			{
                // выполнить аутентификацию 
                if (!EnsureAuthenticate()) return null; 

                // найти содержимое открытого ключа без аутентификации
                publicKeyInfo = GetPublicKeyInfo(keyID, false); 
            }
            else { 
                // найти содержимое открытого ключа без аутентификации
                publicKeyInfo = GetPublicKeyInfo(keyID, false); 

                // найти содержимое открытого ключа с аутентификацией
                if (publicKeyInfo == null) publicKeyInfo = GetPublicKeyInfo(keyID, true); 
            }
            // проверить наличие открытого ключа
            if (publicKeyInfo == null) return null; 

            // раскодировать открытый ключ
            return Provider.DecodePublicKey(publicKeyInfo); 
		}
		private ASN1.ISO.PKIX.SubjectPublicKeyInfo GetPublicKeyInfo(byte[] keyID, bool authenticate)
        {
			// найти сертификат
			PfxSafeBag item = container.FindCertificate(keyID); if (item != null)
            {
                // для незашифрованного элемента
                if (item.Decoded != null)
                {
			        // извлечь содержимое сертификата
			        ASN1.ISO.PKCS.PKCS12.CertBag certBag = 
                        new ASN1.ISO.PKCS.PKCS12.CertBag(item.Decoded.BagValue); 

			        // раскодировать сертификат
			        return new Certificate(certBag.CertValue.Content).PublicKeyInfo; 
                }
                else if (authenticate)
                {
                    // выполнить аутентификацию
                    if (!EnsureAuthenticate()) return null; 

                    // вызвать функцию повторно
                    return GetPublicKeyInfo(keyID, false); 
                }
            }
			// найти запрос на сертификат
			if ((item = container.FindCertificationRequest(keyID)) != null)
            {
                // для незашифрованного элемента
                if (item.Decoded != null)
                {
			        // извлечь содержимое запроса на сертификат 
			        ASN1.ISO.PKCS.PKCS12.SecretBag secretBag = 
				        new ASN1.ISO.PKCS.PKCS12.SecretBag(item.Decoded.BagValue); 

			        // раскодировать запрос на сертификат
			        return new CertificateRequest(secretBag.SecretValue.Content).PublicKeyInfo; 
                }
                else if (authenticate)
                {
                    // выполнить аутентификацию
                    if (!EnsureAuthenticate()) return null; 

                    // вызвать функцию повторно
                    return GetPublicKeyInfo(keyID, false); 
                }
            }
			// найти личный ключ
			if ((item = container.FindPrivateKey(keyID)) != null)
            {
                // для незашифрованного элемента
                if (item.Decoded != null && item.Decoded.BagId.Value == ASN1.ISO.PKCS.PKCS12.OID.bt_key)
                {
			        // извлечь содержимое личного ключа
			        ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo = 
                        new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(item.Decoded.BagValue);

                    // pаскодировать пару ключей
                    using (KeyPair keyPair = Provider.DecodeKeyPair(privateKeyInfo))
                    {
                        // закодировать открытый ключ
                        return keyPair.PublicKey.Encoded;
                    } 
                }
                else if (authenticate)
                {
                    // выполнить аутентификацию
                    if (!EnsureAuthenticate()) return null; 

                    // вызвать функцию повторно
                    return GetPublicKeyInfo(keyID, false); 
                }
            }
            return null; 
		}
		///////////////////////////////////////////////////////////////////////////
		// Найти личный ключ
		///////////////////////////////////////////////////////////////////////////
		public override IPrivateKey GetPrivateKey(byte[] keyID)
		{
            PfxSafeBag item = null; 

			// при полном зашифровании данных 
			if (container.HasEncryptedItems && !container.HasDecryptedItems) 
            {
                // найти элемент с личным ключом с аутентификацией
                Authenticate(); item = FindPrivateKeyBag(keyID, false); 
            }
            else { 
                // найти элемент с личным ключом без аутентификации
                item = FindPrivateKeyBag(keyID, false); 

                // найти элемент с личным ключом с аутентификацией
                if (item == null) item = FindPrivateKeyBag(keyID, true); 
            }
            // проверить наличие личного ключа
            if (item == null) throw new NotFoundException();

		    // извлечь содержимое личного ключа
		    ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo = 
			    new ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo(item.Decoded.BagValue); 

		    // раскодировать ключ
            return Provider.DecodePrivateKey(privateKeyInfo);
        }
		private PfxSafeBag FindPrivateKeyBag(byte[] keyID, bool authenticate)
        {
			// получить личный ключ
			PfxSafeBag item = container.FindPrivateKey(keyID); if (item == null) return null; 
            
            // для зашифрованного элемента
            if (item.Decoded == null || item.Decoded.BagId.Value != ASN1.ISO.PKCS.PKCS12.OID.bt_key)
            {
                // проверить возможность аутентификации
                if (!authenticate) return null; 
                    
                // выполнить аутентификацию и вызвать функцию повторно
                Authenticate(); return FindPrivateKeyBag(keyID, false); 
            }
            return item; 
        }
		///////////////////////////////////////////////////////////////////////////
		// Функции установки
		///////////////////////////////////////////////////////////////////////////
		public override void SetCertificate(byte[] keyID, Certificate certificate)
		{
            // выполнить аутентификацию
            Authenticate();

			// закодировать сертификат
			ASN1.ISO.PKCS.PKCS12.CertBag certBag = new ASN1.ISO.PKCS.PKCS12.CertBag(
				new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.certTypes_x509), 
                new ASN1.OctetString(certificate.Encoded)
			); 
			// найти сертификат по идентификатору
			PfxSafeBag item = FindCertificateBag(keyID, false); if (item != null) 
			{
				// установить значение сертификата
				item.SetValue(new ASN1.ISO.PKCS.PKCS12.SafeBag(
					new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_cert), 
                    certBag, item.Decoded.BagAttributes
				)); 
			}
			// найти запрос по идентификатору
			else if ((item = FindCertificateRequestBag(keyID, false)) != null) 
            {
				// добавить элемент сертификата
                item.Parent.AddObject(new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>(
                    new ASN1.ISO.PKCS.PKCS12.SafeBag(
					    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_cert), 
                        certBag, item.Decoded.BagAttributes), null
                )); 
			}
            else {
				// закодировать идентификатор
				ASN1.OctetString[] encodedID = new ASN1.OctetString[] { new ASN1.OctetString(keyID) }; 

				// создать атрибут идентификатора
				ASN1.ISO.Attributes attributes = new ASN1.ISO.Attributes(new ASN1.ISO.Attribute[] { 
					new ASN1.ISO.Attribute(
                        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.localKeyId), 
						new ASN1.Set<ASN1.OctetString>(encodedID)
				)}); 
				// создать элемент для запроса на сертификат
				ASN1.ISO.PKCS.PKCS12.SafeBag bag = new ASN1.ISO.PKCS.PKCS12.SafeBag(
					new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_cert), 
                    certBag, attributes
				); 
				// добавить новый элемент в контейнер
                container.AddObjects(null, new ASN1.ISO.PKCS.PKCS12.SafeBag[] { bag }, 
                    new PBE.PBECulture[] { null }
                 ); 
            }
            Flush(); 
		}
		public override byte[] SetKeyPair(IRand rand, 
            KeyPair keyPair, KeyUsage keyUsage, KeyFlags keyFlags)
		{
            // закодировать личный ключ
			ASN1.ISO.PKCS.PKCS8.PrivateKeyInfo privateKeyInfo = keyPair.Encode(null); 

            // получить идентификатор ключа
            String keyOID = keyPair.PublicKey.KeyOID; CertificateRequest request = null; 

            // раскодировать открытый ключ
            using (IPrivateKey softPrivateKey = Provider.DecodePrivateKey(privateKeyInfo))
            { 
			    // создать запрос на сертификат
			    request = CreateCertificationRequest(keyPair.PublicKey, softPrivateKey, keyUsage);
            }
			// закодировать запрос на сертификат
			ASN1.ISO.PKCS.PKCS12.SecretBag secretBag = 
			    new ASN1.ISO.PKCS.PKCS12.SecretBag(
				    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.OID.pkcs10), 
                    new ASN1.OctetString(request.Encoded)
			);
			// выполнить аутентификацию
			byte[] keyID = keyPair.KeyID; Authenticate(); if (keyID == null)
            {
			    // определить идентификаторы ключей
                byte[][] keyIDs = GetKeyIDs(keyUsage, true); 

                // указать идентификатор ключа
                if (keyIDs.Length > 0) { keyID = keyIDs[0]; }
            }
			if (keyID != null)
			{
			    // найти сертификат, запрос на сертификат и личный ключ
			    PfxSafeBag itemCert = FindCertificateBag       (keyID, false);
			    PfxSafeBag itemReq  = FindCertificateRequestBag(keyID, false);  
			    PfxSafeBag itemKey  = FindPrivateKeyBag        (keyID, false); 

			    // при наличии ключа с запросом в контейнере
			    if (itemKey != null && itemReq != null)
			    {
				    // установить значение ключа
				    itemKey.SetValue(new ASN1.ISO.PKCS.PKCS12.SafeBag(
					    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_key), 
                        privateKeyInfo, itemKey.Decoded.BagAttributes
				    )); 
				    // установить значение запроса на сертификат
                    itemReq.SetValue(new ASN1.ISO.PKCS.PKCS12.SafeBag(
					    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_secret), 
                        secretBag, itemReq.Decoded.BagAttributes
				    )); 
			    }
			    // при наличии в контейнере только ключа
			    else if (itemKey != null && itemReq == null)
			    {
				    // установить значение ключа
                    itemKey.SetValue(new ASN1.ISO.PKCS.PKCS12.SafeBag(
					    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_key), 
                        privateKeyInfo, itemKey.Decoded.BagAttributes
				    )); 
				    // добавить значение запроса на сертификат
                    container.AddChild(itemKey.Parent, null, new ASN1.ISO.PKCS.PKCS12.SafeBag(
					    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_secret), 
                        secretBag, itemKey.Decoded.BagAttributes
				    )); 
			    }
			    // при наличии в контейнере запроса на сертификат
			    else if (itemKey == null && itemReq != null)
			    {
                    // получить тип парольной защиты
                    PBE.PBECulture culture = cultureFactory.GetPBECulture(rand.Window, keyOID); 
                     
                    // проверить поддержку защиты
                    if (culture == null) throw new NotSupportedException(); 
            
				    // добавить значение ключа
                    container.AddChild(itemReq.Parent, culture, 
                        new ASN1.ISO.PKCS.PKCS12.SafeBag(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_key), 
                            privateKeyInfo, itemReq.Decoded.BagAttributes
				    )); 
				    // установить значение запроса на сертификат
                    itemReq.SetValue(new ASN1.ISO.PKCS.PKCS12.SafeBag(
					    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_secret), 
                        secretBag, itemReq.Decoded.BagAttributes
				    )); 
			    }
			    // при наличии в контейнере сертификата
			    else if (itemKey == null && itemCert != null)
			    {
                    // получить тип парольной защиты
                    PBE.PBECulture culture = cultureFactory.GetPBECulture(rand.Window, keyOID); 
                     
                    // проверить поддержку защиты
                    if (culture == null) throw new NotSupportedException(); 

				    // добавить значение ключа
                    container.AddChild(itemCert.Parent, culture, 
                        new ASN1.ISO.PKCS.PKCS12.SafeBag(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_key), 
                            privateKeyInfo, itemCert.Decoded.BagAttributes
				    )); 
				    // установить значение запроса на сертификат
                    container.AddChild(itemCert.Parent, null, 
                        new ASN1.ISO.PKCS.PKCS12.SafeBag(
					        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_secret), 
                            secretBag, itemCert.Decoded.BagAttributes
				    )); 
			    }
			    // удалить сертификат открытого ключа из контейнера
                if (itemCert != null) itemCert.Parent.RemoveObject(itemCert); 
			}
			else {
		        // сгенерировать случайный номер
		        keyID = new byte[8]; rand.Generate(keyID, 0, keyID.Length); keyID[0] &= 0x7F;
			
		        // найти сертификат, запрос на сертификат и личный ключ
		        PfxSafeBag itemCert = FindCertificateBag       (keyID, false);
		        PfxSafeBag itemReq  = FindCertificateRequestBag(keyID, false);  
		        PfxSafeBag itemKey  = FindPrivateKeyBag        (keyID, false); 

                // до нахождения свободного слота
                while (itemCert != null || itemReq != null || itemKey != null)
                {
                    // сгенерировать случайный номер
                    rand.Generate(keyID, 0, keyID.Length); keyID[0] &= 0x7F;

                    // найти сертификат, запрос на сертификат и личный ключ
		            itemCert = FindCertificateBag       (keyID, false);
		            itemReq  = FindCertificateRequestBag(keyID, false);  
		            itemKey  = FindPrivateKeyBag        (keyID, false); 
                }
			    // закодировать идентификатор
			    ASN1.OctetString[] encodedID = new ASN1.OctetString[] { new ASN1.OctetString(keyID) }; 

			    // создать атрибут идентификатора
			    ASN1.ISO.Attributes attributes = new ASN1.ISO.Attributes(new ASN1.ISO.Attribute[] { 
				    new ASN1.ISO.Attribute(
                        new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.localKeyId), 
					    new ASN1.Set<ASN1.OctetString>(encodedID)
			    )}); 
			    // создать элемент для личного ключа
			    ASN1.ISO.PKCS.PKCS12.SafeBag keyBag = new ASN1.ISO.PKCS.PKCS12.SafeBag(
				    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_key), 
                    privateKeyInfo, attributes
			    ); 
			    // создать элемент для запроса на сертификат
			    ASN1.ISO.PKCS.PKCS12.SafeBag requestBag = new ASN1.ISO.PKCS.PKCS12.SafeBag(
				    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_secret), 
                    secretBag, attributes
			    ); 
                // получить тип парольной защиты
                PBE.PBECulture culture = cultureFactory.GetPBECulture(rand.Window, keyOID); 
                 
                // проверить поддержку защиты
                if (culture == null) throw new NotSupportedException(); 
                
                // добавить новые элементы в контейнер
                container.AddObjects(null, new ASN1.ISO.PKCS.PKCS12.SafeBag[] 
				    {keyBag, requestBag}, new PBE.PBECulture[] {culture, null}
			    ); 
			}
            Flush(); return keyID; 
		}
		public override void DeleteKeyPair(byte[] keyID) 
		{ 
            // выполнить аутентификацию
			Authenticate(); 

			// найти сертификат, запрос на сертификат и личный ключ
			PfxSafeBag itemCert = FindCertificateBag       (keyID, false);
			PfxSafeBag itemReq  = FindCertificateRequestBag(keyID, false);  
			PfxSafeBag itemKey  = FindPrivateKeyBag        (keyID, false); 

			// удалить сертификат открытого ключа из контейнера
            if (itemCert != null) itemCert.Parent.RemoveObject(itemCert); 
			if (itemReq  != null) itemReq .Parent.RemoveObject(itemReq ); 
			if (itemKey  != null) itemKey .Parent.RemoveObject(itemKey ); 

			// вызвать базовую функцию
			base.DeleteKeyPair(keyID); 
		}
		///////////////////////////////////////////////////////////////////////////
		// Создать запрос на сертификат
		///////////////////////////////////////////////////////////////////////////
		private CertificateRequest CreateCertificationRequest( 
			IPublicKey publicKey, IPrivateKey privateKey, KeyUsage keyUsage)
		{
            // указать идентификатор атрибута
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(
                ASN1.ISO.PKIX.OID.at_commonName
            ); 
            // указать значение атрибута
            ASN1.PrintableString name = new ASN1.PrintableString(
                Provider.GetType().Name
            ); 
            // указать атрибут отличимого имени
            ASN1.ISO.PKIX.AttributeTypeValue nameAttribute = 
                new ASN1.ISO.PKIX.AttributeTypeValue(oid, name); 
        
            // указать отдельное отличимое имя 
            ASN1.ISO.PKIX.RelativeDistinguishedName rdn = 
                new ASN1.ISO.PKIX.RelativeDistinguishedName(
                    new ASN1.ISO.PKIX.AttributeTypeValue[] {nameAttribute}
            );
            // указать отличимое имя 
            ASN1.ISO.PKIX.RelativeDistinguishedNames subject = 
                new ASN1.ISO.PKIX.RelativeDistinguishedNames(
                    new ASN1.ISO.PKIX.RelativeDistinguishedName[] {rdn}
            ); 
            // получить параметры алгоритма
            ASN1.ISO.AlgorithmIdentifier signParameters = new ASN1.ISO.AlgorithmIdentifier(
                new ASN1.ObjectIdentifier("2.5.8.0"), null
            ); 
    	    // создать запрос на сертификат
		    return PKI.CreateCertificationRequest(container.Rand, subject, 
                signParameters, publicKey, privateKey, keyUsage, null, null, null, null
		    ); 
    	}
	}
}
