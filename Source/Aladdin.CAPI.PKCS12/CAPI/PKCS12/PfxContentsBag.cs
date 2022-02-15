using System.Collections.Generic;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Неконечный SafeBag-элемент контейнера PKCS12 
	///////////////////////////////////////////////////////////////////////////
	internal class PfxContentsBag : PfxParentItem
	{
		private PfxParentItem					parent;		// родительский узел
		private ASN1.ISO.PKCS.PKCS12.SafeBag	encoded;	// закодированное представление

		protected internal PfxContentsBag(PfxParentItem parent, PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag> decoded)
		{ 
			// установить зашифрованное представление
			this.parent = parent; this.encoded = Pfx.Encrypt(decoded); 

			// преобразовать тип внутренних данных
			ASN1.ISO.PKCS.PKCS12.SafeContents safeContents = 
				new ASN1.ISO.PKCS.PKCS12.SafeContents(encoded.BagValue);

			// для каждого внутреннего объекта
			foreach (ASN1.ISO.PKCS.PKCS12.SafeBag safeBag in safeContents)
			{
                // указать отсутствие шифрования
                PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag> data = 
                    new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>(safeBag, null); 

				// в зависимости от типа внутреннего объекта
				if (safeBag.BagId.Value == ASN1.ISO.PKCS.PKCS12.OID.bt_safeContents)
				{
					// добавить объект в список
					items.Add(new PfxContentsBag(this, 
                        new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>(safeBag, null))); 
				}
				else {
				    // добавить объект в список
                    items.Add(new PfxSafeBag(this, 
                        new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>(safeBag, null))); 
                }
			}
		} 
		protected internal PfxContentsBag(PfxParentItem parent, ASN1.ISO.PKCS.PKCS12.SafeBag encoded)
		{ 
			// сохранить переданные параметры
			this.parent = parent; this.encoded = encoded; 
			
			// преобразовать тип внутренних данных
			ASN1.ISO.PKCS.PKCS12.SafeContents safeContents = 
				new ASN1.ISO.PKCS.PKCS12.SafeContents(encoded.BagValue);

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

		// обработка уведомлений
		protected internal override void OnItemsChange()
 		{
			// получить атрибуты элемента
			ASN1.ISO.Attributes attributes = encoded.BagAttributes; 

			// создать список внутренних объектов
			List<ASN1.ISO.PKCS.PKCS12.SafeBag> list = 
				new List<ASN1.ISO.PKCS.PKCS12.SafeBag>();

			// для каждого внутреннего объекта
			foreach (PfxItem item in items)
			{
				// добавить объекты в список
				list.Add(new ASN1.ISO.PKCS.PKCS12.SafeBag(item.Encoded));
			}
			// объединить объекты из списка
			ASN1.ISO.PKCS.PKCS12.SafeContents safeContents = 
				new ASN1.ISO.PKCS.PKCS12.SafeContents(list.ToArray());

			// сохранить закодированное представление
			encoded = new ASN1.ISO.PKCS.PKCS12.SafeBag(
				new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS12.OID.bt_safeContents), 
                safeContents, attributes
			);
			// уведомить родительский узел
			parent.OnItemsChange();
		}
	}
}
