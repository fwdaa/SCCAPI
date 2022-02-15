using System;
using System.Collections.Generic;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Неконечный SafeContents-элемент контейнера PKCS12 
	///////////////////////////////////////////////////////////////////////////
	internal class PfxSafeContents : PfxParentItem
	{
		private PfxParentItem				parent;		// родительский узел
		private PfxEncryptor				encryptor;	// функция зашифрования элемента
		private ASN1.ISO.PKCS.ContentInfo	encoded;	// закодированное представление

		protected internal PfxSafeContents(PfxParentItem parent, 
            PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>[] safeBags, PfxEncryptor encryptor)
		{
			// создать список элементов
			List<ASN1.ISO.PKCS.PKCS12.SafeBag> listSafeBags = 
				new List<ASN1.ISO.PKCS.PKCS12.SafeBag>(); 

			// для каждого элемента
			for (int i = 0; i < safeBags.Length; i++)
			{
				// при необходимости зашифровать элемент
				listSafeBags.Add(Pfx.Encrypt(safeBags[i])); 
			}
			// объединить элементы из списка
			ASN1.ISO.PKCS.PKCS12.SafeContents safeContents = 
				new ASN1.ISO.PKCS.PKCS12.SafeContents(listSafeBags.ToArray()); 

			// при необходимости зашифрования
			this.parent = parent; this.encryptor = encryptor; if (encryptor != null)
			{
				// зашифровать элемент
				byte[] encrypted = encryptor.Encrypt(safeContents.Encoded); 

				// раскодировать зашифрованный элемент
				encoded = new ASN1.ISO.PKCS.ContentInfo(ASN1.Encodable.Decode(encrypted)); 
			}
			else {
				// закодировать данные
				ASN1.OctetString encodable = new ASN1.OctetString(safeContents.Encoded); 

				// закодировать данные
				encoded = new ASN1.ISO.PKCS.ContentInfo(
                    new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS7.OID.data), encodable); 
			}
			// для каждого внутреннего объекта
			for (int i = 0; i < safeBags.Length; i++)
			{
				// в зависимости от типа внутреннего объекта
				if (safeBags[i].Content.BagId.Value == ASN1.ISO.PKCS.PKCS12.OID.bt_safeContents)
				{
					// добавить объект в список
					items.Add(new PfxContentsBag(this, safeBags[i])); 
				}
				// добавить объект в список
				else items.Add(new PfxSafeBag(this, safeBags[i])); 
			}
		}
		protected internal PfxSafeContents(PfxParentItem parent, ASN1.ISO.PKCS.ContentInfo encoded)
		{
			// сохранить переданные параметры
			this.parent = parent; this.encoded = encoded; 
			
			// проверить отсутствие шифрования
			if (encoded.ContentType.Value != ASN1.ISO.PKCS.PKCS7.OID.data) return; 

			// извлечь данные
			byte[] encodedData = new ASN1.OctetString(encoded.Inner).Value; 

			// раскодировать незашифрованный элемент
			ASN1.ISO.PKCS.PKCS12.SafeContents safeContents = 
				new ASN1.ISO.PKCS.PKCS12.SafeContents(ASN1.Encodable.Decode(encodedData));

			// для каждого внутреннего объекта
			foreach (ASN1.ISO.PKCS.PKCS12.SafeBag safeBag in safeContents)
			{
				// в зависимости от типа внутреннего объекта
				if (safeBag.BagId.Value == ASN1.ISO.PKCS.PKCS12.OID.bt_safeContents)
				{
					// добавить объект в список
					items.Add(new PfxContentsBag(this, safeBag)); 
				}
				// добавить объект в список
				else items.Add(new PfxSafeBag(this, safeBag)); 
			}
		}
		// закодированное представление и родительский узел
		public override ASN1.IEncodable Encoded { get { return encoded; } } 
		public override PfxParentItem	Parent  { get { return parent;  } } 

		// признак наличия открытых данных
		public override bool HasDecryptedItems { get 
		{ 
			// проверить наличие шифрования
			if (encoded.ContentType.Value != ASN1.ISO.PKCS.PKCS7.OID.data) return false; 

			// вызвать базовую функцию
			return base.HasDecryptedItems; 
		}}
		// признак наличия закрытых данных
		public override bool HasEncryptedItems { get 
		{ 
			// проверить наличие шифрования
			if (encoded.ContentType.Value != ASN1.ISO.PKCS.PKCS7.OID.data) return true; 

			// вызвать базовую функцию
			return base.HasEncryptedItems; 
		}}
		// расшифровать элемент
		protected internal override void Decrypt(PfxDecryptor decryptor)
		{
			// проверить наличие шифрования
			if (encoded.ContentType.Value != ASN1.ISO.PKCS.PKCS7.OID.data)
			{
				// указать тип зашифрованных данных
				Type encryptionType = typeof(ASN1.ISO.PKCS.PKCS7.EncryptedData); 

				// скорректировать тип зашифрованных данных
				if (encoded.ContentType.Value == ASN1.ISO.PKCS.PKCS7.OID.envelopedData)
				{
					// скорректировать тип зашифрованных данных
					encryptionType = typeof(ASN1.ISO.PKCS.PKCS7.EnvelopedData); 
				}
				// расшифровать данные
				PfxData<byte[]> decryptedData = decryptor.Decrypt(
                    encoded.Inner.Encoded, encryptionType
                ); 
				// раскодировать элемент
				ASN1.ISO.PKCS.PKCS12.SafeContents safeContents = 
					new ASN1.ISO.PKCS.PKCS12.SafeContents(
                        ASN1.Encodable.Decode(decryptedData.Content)
                );
				// для каждого внутреннего объекта
				foreach (ASN1.ISO.PKCS.PKCS12.SafeBag safeBag in safeContents)
				{
					// в зависимости от типа внутреннего объекта
					if (safeBag.BagId.Value == ASN1.ISO.PKCS.PKCS12.OID.bt_safeContents)
					{
						// добавить объект в список
						items.Add(new PfxContentsBag(this, safeBag)); 
					}
					// добавить объект в список
					else items.Add(new PfxSafeBag(this, safeBag)); 
				}
			}
			// вызвать базовую функцию
			base.Decrypt(decryptor); 
		}
		// обработка уведомлений
		protected internal override void OnItemsChange()
		{
			// определить тип содержимого
			string type = encoded.ContentType.Value; 

			// создать список внутренних объектов
			List<ASN1.ISO.PKCS.PKCS12.SafeBag> list = new List<
				ASN1.ISO.PKCS.PKCS12.SafeBag>();

			// для каждого внутреннего объекта
			foreach (PfxItem item in items)
			{
				// добавить объекты в список
				list.Add(new ASN1.ISO.PKCS.PKCS12.SafeBag(item.Encoded));
			}
			// объединить объекты из списка
			ASN1.ISO.PKCS.PKCS12.SafeContents safeContents = 
				new ASN1.ISO.PKCS.PKCS12.SafeContents(list.ToArray());

			// при наличии шифрования
			ASN1.IEncodable encodable; if (encryptor != null)
			{
				// зашифровать данные
				encodable = ASN1.Encodable.Decode(encryptor.Encrypt(safeContents.Encoded)); 
			}
			else { 
				// закодировать данные
				encodable = new ASN1.OctetString(safeContents.Encoded); 
			}
			// закодировать данные
			encoded = new ASN1.ISO.PKCS.ContentInfo(
                new ASN1.ObjectIdentifier(type), encodable); parent.OnItemsChange();
		}
	}
}
