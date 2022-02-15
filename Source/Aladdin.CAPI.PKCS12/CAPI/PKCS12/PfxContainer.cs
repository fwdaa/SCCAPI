using System;
using System.Collections.Generic;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Контейнер PKCS12
	///////////////////////////////////////////////////////////////////////////
	public abstract class PfxContainer : PfxParentItem, PfxDecryptor
	{
        // содержимое контейнера и генератор случайных данных 
		protected ASN1.ISO.PKCS.PKCS12.PFX content; private IRand rand;      
		
		// конструктор
		protected PfxContainer(ASN1.ISO.PKCS.PKCS12.PFX content, IRand rand) 
		{ 
			// сохранить переданные параметры
			this.content = content; this.rand = RefObject.AddRef(rand); 

			// извлечь элементы контейнера
			ASN1.ISO.PKCS.PKCS12.AuthenticatedSafe collection = content.GetAuthSafeContent(); 

			// для каждого элемента
			foreach (ASN1.ISO.PKCS.ContentInfo info in collection) 
			{
				// добавить элемент в список
				items.Add(new PfxSafeContents(this, info)); 
			}
		}
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
		    RefObject.Release(rand); base.OnDispose();
        }
		// генератор случайных данных
		public IRand Rand { get { return rand; }}

		///////////////////////////////////////////////////////////////////////
		// Расширение функциональности
		///////////////////////////////////////////////////////////////////////
		public virtual byte[] Encrypt(PBE.PBECulture culture, byte[] decryptedData, Type encryptionType)
        {
            // зашифрование отсутствует
            return decryptedData; 
        }
		public virtual PfxData<byte[]> Decrypt(byte[] encryptedData, Type encryptionType)
        {
            // расшифрование отсутствует
            return new PfxData<byte[]>(encryptedData, null); 
        }
		// функция обратного вызова при изменении коллекции
		protected abstract void OnChange(ASN1.ISO.PKCS.PKCS12.AuthenticatedSafe authenticatedSafe); 

		///////////////////////////////////////////////////////////////////////
		// Переопределение унаследованных функций
		///////////////////////////////////////////////////////////////////////
		public override PfxParentItem Parent { get { return null; } } 

		// изменение дочерних элементов
		protected internal override void OnItemsChange() 
		{
			// создать список внутренних элементов
			List<ASN1.ISO.PKCS.ContentInfo> list = new List<ASN1.ISO.PKCS.ContentInfo>(); 

			// для каждого элемента
			foreach (PfxItem item in this)
			{
				// добавить элемент в список
				list.Add((ASN1.ISO.PKCS.ContentInfo)item.Encoded); 
			}
			// выполнить действие по изменению 
			OnChange(new ASN1.ISO.PKCS.PKCS12.AuthenticatedSafe(list.ToArray())); 
		}
		// закодированное представление
		public override ASN1.IEncodable Encoded { get { return content; } }

		///////////////////////////////////////////////////////////////////////
		// Добавление дочерних элементов
		///////////////////////////////////////////////////////////////////////
		private PfxEncryptor GetItemEncryptor(string bagType, PBE.PBECulture culture)
		{
            // проверить необходимость зашифрования
			if (bagType != ASN1.ISO.PKCS.PKCS12.OID.bt_key || culture == null) return null; 

			// определить тип зашифрованных данных
			Type type = typeof(ASN1.ISO.PKCS.PKCS8.EncryptedPrivateKeyInfo); 

			// создать функцию зашифрования данных
            return new PfxEncryptor.Container(this, culture, type); 
		}
        public virtual void AddObjects(PBE.PBECulture culture,  
            ASN1.ISO.PKCS.PKCS12.SafeBag[] safeBags, PBE.PBECulture[] cultures) 
		{
			// создать список функций зашифрования
			PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>[] bags = 
                new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>[safeBags.Length]; 

			// для всех дочерних элементов
			for (int i = 0; i < safeBags.Length; i++)
			{
				// указать функцию зашифрования
                PfxEncryptor encryptor = GetItemEncryptor(safeBags[i].BagId.Value, cultures[i]); 

                // связать функцию шифрования с элементом
                bags[i] = new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>(safeBags[i], encryptor); 
			}
            // добавить новый элемент
            AddObjects(bags, (culture !=  null) ? new PfxEncryptor.Container(this, culture, null) : null); 
		}
        public void AddChild(PfxParentItem parent, PBE.PBECulture culture, ASN1.ISO.PKCS.PKCS12.SafeBag safeBag) 
		{
			// создать функцию зашифрования
            PfxEncryptor encryptor = GetItemEncryptor(safeBag.BagId.Value, culture); 

			// добавить данные
			parent.AddObject(new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>(safeBag, encryptor)); 
		}
		///////////////////////////////////////////////////////////////////////
		// Найти элемент коллекции
		///////////////////////////////////////////////////////////////////////
		public PfxSafeBag FindObject(string type, byte[] id)
		{
			// найти требуемый элемент 
			PfxContainerSafeBag[] items = FindObjects(new PfxFilter.Object(type, id));

			// проверить наличие элемента
			return items.Length > 0 ? items[0].SafeBag : null; 
		}
		///////////////////////////////////////////////////////////////////////
		// Управление запросами на сертификат
		///////////////////////////////////////////////////////////////////////
		public PfxContainerSafeBag[] FindCertificationRequests(PfxFilter callback)
		{
			// получить запросы на сертификат открытого ключа
			return FindObjects(new PfxFilter.CertificationRequest(callback));
		}
		public PfxSafeBag FindCertificationRequest(byte[] keyID)
		{
		    // указать фильтр поиска по идентификатору
		    PfxFilter filter = new PfxFilter.Object(ASN1.ISO.PKCS.PKCS12.OID.bt_secret, keyID);
 
			// получить запрос на сертификат открытого ключа
			PfxContainerSafeBag[] items = FindCertificationRequests(filter); 

			// проверить наличие запроса на сертификат
			return items.Length > 0 ? items[0].SafeBag : null; 
		}
		///////////////////////////////////////////////////////////////////////
		// Управление сертификатами
		///////////////////////////////////////////////////////////////////////
		public PfxContainerSafeBag[] FindCertificates(PfxFilter callback)
		{
			// получить сертификаты открытого ключа
			return FindObjects(new PfxFilter.Certificate(callback));
		}
		public PfxSafeBag FindCertificate(byte[] keyID)
		{
		    // указать фильтр поиска по идентификатору
		    PfxFilter filter = new PfxFilter.Object(ASN1.ISO.PKCS.PKCS12.OID.bt_cert, keyID);

			// получить сертификаты открытого ключа
			PfxContainerSafeBag[] items = FindCertificates(filter);

			// проверить наличие сертификата
			return items.Length > 0 ? items[0].SafeBag : null; 
		}
		///////////////////////////////////////////////////////////////////////
		// Управление личными ключами
		///////////////////////////////////////////////////////////////////////
		public PfxContainerSafeBag[] FindPrivateKeys(PfxFilter callback)
		{
			// получить личные ключи
			return FindObjects(new PfxFilter.PrivateKey(callback));
		}
		public PfxSafeBag FindPrivateKey(byte[] keyID)
		{
			// получить закодированный личный ключ
			PfxSafeBag safeBag = FindObject(ASN1.ISO.PKCS.PKCS12.OID.bt_key, keyID);

            // вернуть закодированный личный ключ
            return (safeBag != null) ? safeBag : FindObject(ASN1.ISO.PKCS.PKCS12.OID.bt_shroudedKey, keyID); 
		}
	}
}
