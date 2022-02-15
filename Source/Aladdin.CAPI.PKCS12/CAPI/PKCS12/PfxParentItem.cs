using System.Collections;
using System.Collections.Generic;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Неконечный элемент контейнера PKCS12 
	///////////////////////////////////////////////////////////////////////////
	public abstract class PfxParentItem : PfxItem, IEnumerable<PfxItem>
	{
		// дочерние элементы
		protected List<PfxItem> items;		

		// конструктор
		protected PfxParentItem() { items = new List<PfxItem>(); }

        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            foreach (PfxItem item in items) RefObject.Release(item); 

            // вызвать базовую функцию
            base.OnDispose();
        }
		// получить элемент коллекции
		public PfxItem this[int i] { get { return items[i]; } }  
			
		// получить размер коллекции
		public int Length { get { return items.Count; } } 

		// перечислитель элементов
		public IEnumerator<PfxItem> GetEnumerator() { return items.GetEnumerator(); }

		// перечислитель элементов
		IEnumerator IEnumerable.GetEnumerator() { return items.GetEnumerator(); }

		// признак наличия открытых данных
		public override bool HasDecryptedItems { get 
		{ 
			// для всех дочерних элементов
			foreach (PfxItem item in items) 
			{ 
				// проверить наличие шифрования
				if (item.HasDecryptedItems) return true; 
			}
			return false; 
		}}
		// признак наличия закрытых данных
		public override bool HasEncryptedItems { get 
		{ 
			// для всех дочерних элементов
			foreach (PfxItem item in items) 
			{ 
				// проверить наличие шифрования
				if (item.HasEncryptedItems) return true; 
			}
			return false; 
		}}
		// расшифровать элемент
		protected internal override void Decrypt(PfxDecryptor decryptor)
		{
			// расшифровать все дочерние элементы
            foreach (PfxItem item in items) item.Decrypt(decryptor); 
		}
        // изменить значение
        protected internal override void Change()
        {
			// изменить все дочерние элементы
            foreach (PfxItem item in items) item.Change(); 
        }
		// изменение дочерних элементов
		protected internal virtual void OnItemsChange() {}

		// найти требуемый элемент
		public PfxContainerSafeBag[] FindObjects(PfxFilter callback)
		{
			// создать список найденных элементов
			List<PfxContainerSafeBag> objs = new List<PfxContainerSafeBag>(); 

			// для каждого элемента коллекции
			foreach (PfxItem item in this)
			{
				// для внутренней коллекции
				if (item is PfxParentItem) 
				{
					// найти элементы внутренней коллекции
					objs.AddRange(((PfxParentItem)item).FindObjects(callback));
				}
				else if (item is PfxSafeBag)
				{
					// извлечь расшифрованное значение элемента
					ASN1.ISO.PKCS.PKCS12.SafeBag safeBag = ((PfxSafeBag)item).Decoded; 

					// указать зашифрованное значение элемента
					if (safeBag == null) safeBag = (ASN1.ISO.PKCS.PKCS12.SafeBag)((PfxSafeBag)item).Encoded; 
                    
                    // определить идентификатор элемента
                    byte[] keyID = safeBag.LocalKeyID; 

                    // при отсутствии идентификатора
                    if (keyID == null && safeBag.BagAttributes != null) 
                    {
                        // получить закодированное представление атрибутов
                        byte[] encoded = safeBag.BagAttributes.Encoded; 

                        // создать алгоритм хэширования
                        using (Hash hash = new ANSI.Hash.SHA1())
                        {
                            // вычислить хэш-значение от атрибутов
                            keyID = hash.HashData(encoded, 0, encoded.Length); 
                        }
                    }
					try { 
						// проверить критерий поиска
						if (callback != null && !callback.IsMatch(safeBag, keyID)) continue; 

                        // добавить элемент в список
                        objs.Add(new PfxContainerSafeBag((PfxSafeBag)item, keyID)); 
					}
					catch {}
				}
			}
			return objs.ToArray();
		}
		// добавить дочерние элементы
		public void AddObjects(PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>[] safeBags, PfxEncryptor encryptor)
		{
			// создать новый элемент
			PfxSafeContents item = new PfxSafeContents(this, safeBags, encryptor); 

			// добавить новый элемент
            items.Insert(items.Count, item); OnItemsChange(); 
		}
		// добавить дочерний элемент
		public void AddObject(PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag> safeBag)
		{
			// в зависимости от типа внутреннего объекта
			if (safeBag.Content.BagId.Value == ASN1.ISO.PKCS.PKCS12.OID.bt_safeContents)
			{
				// добавить объект в список
				items.Insert(items.Count, new PfxContentsBag(this, safeBag)); 
			}
			// добавить объект в список
            else items.Insert(items.Count, new PfxSafeBag(this, safeBag)); OnItemsChange();
		}
		// удалить требуемый элемент
		public void RemoveObject(PfxSafeBag pfxSafeBag)
		{
			// удалить требуемый элемент
            items.Remove(pfxSafeBag); OnItemsChange();
		}
	}
}
