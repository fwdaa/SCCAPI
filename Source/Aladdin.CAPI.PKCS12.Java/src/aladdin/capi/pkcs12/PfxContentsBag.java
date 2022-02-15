package aladdin.capi.pkcs12;
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Неконечный SafeBag-элемент контейнера PKCS12 
///////////////////////////////////////////////////////////////////////////
public class PfxContentsBag extends PfxParentItem
{
	private final PfxParentItem	parent;	// родительский узел
	private SafeBag            encoded;	// закодированное представление

	protected PfxContentsBag(PfxParentItem parent, PfxData<SafeBag> decoded) 
        throws IOException
	{ 
		// сохранить переданные параметры
		this.parent = parent; this.encoded = Pfx.encrypt(decoded); 

		// преобразовать тип внутренних данных
		SafeContents safeContents = new SafeContents(encoded.bagValue());

		// для каждого внутреннего объекта
		for (SafeBag safeBag : safeContents)
		{
			// в зависимости от типа внутреннего объекта
			if (safeBag.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SAFE_CONTENTS))
			{
				// добавить объект в список
				items.add(new PfxContentsBag(this, new PfxData<SafeBag>(safeBag, null))); 
			}
			// добавить объект в список
			else items.add(new PfxSafeBag(this, new PfxData<SafeBag>(safeBag, null))); 
		}
	} 
	protected PfxContentsBag(PfxParentItem parent, SafeBag encoded) throws IOException
	{ 
		// сохранить переданные параметры
		this.parent = parent; this.encoded = encoded; 
			
		// преобразовать тип внутренних данных
		SafeContents safeContents = new SafeContents(encoded.bagValue());

        // для каждого внутреннего объекта
		for (SafeBag safeBag : safeContents)
		{
			// в зависимости от типа внутреннего объекта
			if (safeBag.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SAFE_CONTENTS))
			{
				// добавить объект в список
				items.add(new PfxContentsBag(this, safeBag)); 
			}
			// добавить объект в список
			else items.add(new PfxSafeBag(this, safeBag)); 
		}
	} 
	// закодированное представление и родительский узел
	@Override public IEncodable     encoded() { return encoded; } 
	@Override public PfxParentItem	parent () { return parent;  } 

	// обработка уведомлений
	@Override protected void onItemsChange() throws IOException
 	{
		// получить атрибуты элемента
		Attributes attributes = encoded.bagAttributes(); 

		// создать список внутренних объектов
		List<SafeBag> list = new ArrayList<SafeBag>();

		// для каждого внутреннего объекта
		for (PfxItem item : items)
		{
			// добавить объекты в список
			list.add(new SafeBag(item.encoded()));
		}
		// объединить объекты из списка
		SafeContents safeContents = new SafeContents(list.toArray(new SafeBag[0]));

		// сохранить закодированное представление
		encoded = new SafeBag(new ObjectIdentifier(
            aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SAFE_CONTENTS), safeContents, attributes
        );
		// уведомить родительский узел
		parent.onItemsChange();
	}
}
