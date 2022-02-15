package aladdin.capi.pkcs12;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkcs.*; 
import aladdin.asn1.iso.pkcs.pkcs7.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Неконечный SafeContents-элемент контейнера PKCS12 
///////////////////////////////////////////////////////////////////////////
public class PfxSafeContents extends PfxParentItem
{
	private final PfxParentItem	parent;		// родительский узел
	private PfxEncryptor        encryptor;	// функция зашифрования элемента
	private ContentInfo         encoded;	// закодированное представление

	protected PfxSafeContents(PfxParentItem parent, 
        List<PfxData<SafeBag>> safeBags, PfxEncryptor encryptor) 
        throws IOException
	{
		// создать список элементов
		List<SafeBag> listSafeBags = new ArrayList<SafeBag>(); 

		// для каждого элемента
		for (int i = 0; i < safeBags.size(); i++)
		{
			// при необходимости зашифровать элемент
			listSafeBags.add(Pfx.encrypt(safeBags.get(i))); 
		}
		// объединить элементы из списка
		SafeContents safeContents = new SafeContents(listSafeBags.toArray(new SafeBag[0])); 

        // при необходимости зашифрования
		this.parent = parent; this.encryptor = encryptor; if (encryptor != null)
		{
			// зашифровать элемент
			byte[] encrypted = encryptor.encrypt(safeContents.encoded()); 

			// раскодировать зашифрованный элемент
			encoded = new ContentInfo(Encodable.decode(encrypted)); 
		}
		else {
			// закодировать данные
			OctetString encodable = new OctetString(safeContents.encoded()); 

			// закодировать данные
			encoded = new ContentInfo(new ObjectIdentifier(
                aladdin.asn1.iso.pkcs.pkcs7.OID.DATA), encodable
            ); 
		}
		// для каждого внутреннего объекта
		for (int i = 0; i < safeBags.size(); i++)
		{
            // получить внутренний объект
            PfxData<SafeBag> safeBag = safeBags.get(i); 
            
			// в зависимости от типа внутреннего объекта
			if (safeBag.content.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SAFE_CONTENTS))
			{
				// добавить объект в список
				items.add(new PfxContentsBag(this, safeBag)); 
			}
			// добавить объект в список
			else items.add(new PfxSafeBag(this, safeBag)); 
		}
	}
	protected PfxSafeContents(PfxParentItem parent, ContentInfo encoded) throws IOException
	{
		// сохранить переданные параметры
		this.parent = parent; this.encoded = encoded; 
			
		// проверить отсутствие шифрования
		if (!encoded.contentType().value().equals(aladdin.asn1.iso.pkcs.pkcs7.OID.DATA)) return; 

		// извлечь данные
		byte[] encodedData = new OctetString(encoded.inner()).value(); 

		// раскодировать незашифрованный элемент
		SafeContents safeContents = new SafeContents(Encodable.decode(encodedData));

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
	@Override public PfxParentItem  parent () { return parent;  } 

    // признак наличия открытых данных
	@Override public boolean hasDecryptedItems()
	{ 
		// проверить наличие шифрования
		if (!encoded.contentType().value().equals(aladdin.asn1.iso.pkcs.pkcs7.OID.DATA)) return false; 

		// вызвать базовую функцию
		return super.hasDecryptedItems(); 
	}
	// признак наличия закрытых данных
	@Override public boolean hasEncryptedItems()
	{ 
		// проверить наличие шифрования
		if (!encoded.contentType().value().equals(aladdin.asn1.iso.pkcs.pkcs7.OID.DATA)) return true; 

		// вызвать базовую функцию
		return super.hasEncryptedItems(); 
	}
	// расшифровать элемент
	@Override protected void decrypt(PfxDecryptor decryptor) throws IOException
	{
		// проверить наличие шифрования
		if (!encoded.contentType().value().equals(aladdin.asn1.iso.pkcs.pkcs7.OID.DATA))
		{
			// указать тип зашифрованных данных
			java.lang.Class<? extends IEncodable> encryptionType = EncryptedData.class; 

			// скорректировать тип зашифрованных данных
			if (encoded.contentType().value().equals(aladdin.asn1.iso.pkcs.pkcs7.OID.ENVELOPED_DATA))
			{
				// скорректировать тип зашифрованных данных
				encryptionType = EnvelopedData.class; 
			}
			// расшифровать данные
			PfxData<byte[]> decryptedData = decryptor.decrypt(encoded.inner().encoded(), encryptionType); 
            
			// раскодировать элемент
			SafeContents safeContents = new SafeContents(Encodable.decode(decryptedData.content));

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
		// вызвать базовую функцию
		super.decrypt(decryptor); 
	}
	// обработка уведомлений
	@Override protected void onItemsChange() throws IOException
	{
		// определить тип содержимого
		String type = encoded.contentType().value(); 

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

		// при наличии шифрования
		IEncodable encodable; if (encryptor != null)
		{
			// зашифровать данные
			encodable = Encodable.decode(encryptor.encrypt(safeContents.encoded())); 
		}
		else { 
			// закодировать данные
			encodable = new OctetString(safeContents.encoded()); 
		}
		// закодировать данные
		encoded = new ContentInfo(new ObjectIdentifier(type), encodable); 
        
		// уведомить родительский узел
		parent.onItemsChange();
	}
}
