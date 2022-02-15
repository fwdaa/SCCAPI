package aladdin.capi.pkcs12;
import aladdin.*; 
import aladdin.capi.*;
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Неконечный элемент контейнера PKCS12 
///////////////////////////////////////////////////////////////////////////
public abstract class PfxParentItem extends PfxItem implements Iterable<PfxItem>
{
	// дочерние элементы
	protected List<PfxItem> items;		

	// конструктор
	protected PfxParentItem() { items = new ArrayList<PfxItem>(); }

    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить выделенные ресурсы
        for (PfxItem item : items) RefObject.release(item); super.onClose();
    }
	// получить элемент коллекции
	public PfxItem get(int i) { return items.get(i); }  
			
	// получить размер коллекции
	public int size() { return items.size(); } 

    // перечислитель объектов
    @Override public final Iterator<PfxItem> iterator() { return items.iterator(); }
    
	// признак наличия открытых данных
	@Override public boolean hasDecryptedItems()
	{ 
		// для всех дочерних элементов
		for (PfxItem item : items) 
		{ 
			// проверить наличие шифрования
			if (item.hasDecryptedItems()) return true; 
		}
		return false; 
	}
    // признак наличия закрытых данных
	@Override public boolean hasEncryptedItems()
	{ 
		// для всех дочерних элементов
		for (PfxItem item : items) 
		{ 
			// проверить наличие шифрования
			if (item.hasEncryptedItems()) return true; 
		}
		return false; 
	}
	// расшифровать элемент
	@Override protected void decrypt(PfxDecryptor decryptor) throws IOException
	{
		// расшифровать все дочерние элементы
		for (PfxItem item : items) item.decrypt(decryptor); 
	}
    // изменить значение
    @Override protected void change() throws IOException
    {
        // изменить все дочерние элементы
        for (PfxItem item : items) item.change(); 
    }
	// изменение дочерних элементов
	protected void onItemsChange() throws IOException {}

	// найти требуемый элемент
	public PfxContainerSafeBag[] findObjects(PfxFilter callback)
	{
		// создать список найденных элементов
		List<PfxContainerSafeBag> objs = new ArrayList<PfxContainerSafeBag>(); 

		// для каждого элемента коллекции
		for (PfxItem item : this)
		{
			// для внутренней коллекции
			if (item instanceof PfxParentItem) 
			{
				// найти элементы внутренней коллекции
                PfxContainerSafeBag[] objects = ((PfxParentItem)item).findObjects(callback); 
                
                // добавить элементы внутренней коллекции
				objs.addAll(Arrays.asList(objects));
			}
			else if (item instanceof PfxSafeBag)
			{
				// извлечь значение элемента
				SafeBag safeBag = ((PfxSafeBag)item).decoded(); 

				// указать зашифрованное значение элемента
				if (safeBag == null) safeBag = (SafeBag)((PfxSafeBag)item).encoded(); 
                    
                // определить идентификатор элемента
                byte[] keyID = safeBag.localKeyID(); 

                // при отсутствии идентификатора
                if (keyID == null && safeBag.bagAttributes() != null)
                {
                    // получить закодированное представление атрибутов
                    byte[] encoded = safeBag.bagAttributes().encoded(); 

                    // создать алгоритм хэширования
                    try (Hash hash = new aladdin.capi.ansi.hash.SHA1())
                    {
                        // вычислить хэш-значение от атрибутов
                        keyID = hash.hashData(encoded, 0, encoded.length); 
                    }
                    // обработать неожидаемую ошибку
                    catch (IOException e) { throw new RuntimeException(e); }
                }
				try { 
					// проверить критерий поиска
					if (callback != null && !callback.isMatch(safeBag, keyID)) continue; 

                    // добавить элемент в список
                    objs.add(new PfxContainerSafeBag((PfxSafeBag)item, keyID)); 
                }
				catch (Throwable e) {}
			}
		}
        // вернуть найденные элементы
		return objs.toArray(new PfxContainerSafeBag[0]);
	}
	// добавить дочерние элементы
	void addObjects(List<PfxData<SafeBag>> safeBags, PfxEncryptor encryptor) 
        throws IOException
	{
		// создать новый элемент
		PfxSafeContents item = new PfxSafeContents(this, safeBags, encryptor); 

		// добавить новый элемент
		items.add(0, item); onItemsChange(); 
	}
	// добавить дочерний элемент
	void addObject(PfxData<SafeBag> data) throws IOException
	{
		// в зависимости от типа внутреннего объекта
		if (data.content.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SAFE_CONTENTS))
		{
			// добавить объект в список
			items.add(0, new PfxContentsBag(this, data)); 
		}
		// добавить объект в список
		else items.add(0, new PfxSafeBag(this, data)); onItemsChange();
	}
	// удалить требуемый элемент
	public void removeObject(PfxSafeBag pfxSafeBag) throws IOException
	{
		// удалить требуемый элемент
		items.remove(pfxSafeBag); onItemsChange();
	}
}
