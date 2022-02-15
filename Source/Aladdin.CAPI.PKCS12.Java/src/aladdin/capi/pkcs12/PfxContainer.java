package aladdin.capi.pkcs12; 
import aladdin.*;
import aladdin.asn1.*; 
import aladdin.asn1.iso.pkcs.*; 
import aladdin.asn1.iso.pkcs.pkcs8.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import aladdin.capi.*; 
import aladdin.capi.pbe.*; 
import java.io.*; 
import java.util.*; 
        
///////////////////////////////////////////////////////////////////////////
// Контейнер PKCS12
///////////////////////////////////////////////////////////////////////////
public abstract class PfxContainer extends PfxParentItem implements PfxDecryptor
{
    // содержимое контейнера и генератор случайных данных 
	protected PFX content; private final IRand rand;    
		
	// конструктор
	protected PfxContainer(PFX content, IRand rand) throws IOException
	{ 
		// сохранить переданные параметры
		this.content = content; this.rand = RefObject.addRef(rand); 
        
		// извлечь элементы контейнера
		AuthenticatedSafe collection = content.getAuthSafeContent(); 

		// для каждого элемента
		for (ContentInfo info : collection) 
		{
			// добавить элемент в список
			items.add(new PfxSafeContents(this, info)); 
		}
	}
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException   
    {
        // освободить выделенные ресурсы
		RefObject.release(rand); super.onClose();
    }
    // генератор случайных данных
    public final IRand rand() { return rand; }
    
	///////////////////////////////////////////////////////////////////////
	// Расширение функциональности
	///////////////////////////////////////////////////////////////////////

	// зашифровать элемент
	public byte[] encrypt(PBECulture culture, byte[] decryptedData, 
        Class<? extends IEncodable> encryptionType) throws IOException
    {
        // зашифрование отсутствует
        return decryptedData; 
    }
    @Override public PfxData<byte[]> decrypt(byte[] encryptedData, 
        Class<? extends IEncodable> encryptionType) throws IOException
    {
        // расшифрование отсутствует
        return new PfxData<byte[]>(encryptedData, null); 
    }
    // функция обратного вызова при изменении коллекции
	protected abstract void onChange( 
        AuthenticatedSafe authenticatedSafe) throws IOException; 
    
	///////////////////////////////////////////////////////////////////////
	// Переопределение унаследованных функций
	///////////////////////////////////////////////////////////////////////
	@Override public PfxParentItem parent() { return null; } 

	// изменение дочерних элементов
	@Override protected void onItemsChange() throws IOException
	{
		// создать список внутренних элементов
		List<ContentInfo> list = new ArrayList<ContentInfo>(); 

		// для каждого элемента
		for (PfxItem item : this)
		{
			// добавить элемент в список
			list.add((ContentInfo)item.encoded()); 
		}
		// выполнить действие по изменению 
		onChange(new AuthenticatedSafe(list.toArray(new ContentInfo[0]))); 
	}
	// закодированное представление
	@Override public IEncodable encoded() { return content; }

	///////////////////////////////////////////////////////////////////////
	// Добавление дочерних элементов
	///////////////////////////////////////////////////////////////////////
    private PfxEncryptor getItemEncryptor(String bagType, PBECulture culture)
	{
		// проверить необходимость зашифрования
		if (!bagType.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY) || culture == null) return null; 

		// создать функцию зашифрования данных
		return new PfxEncryptor.Container(this, culture, EncryptedPrivateKeyInfo.class); 
	}
	public void addObjects(PBECulture culture, SafeBag[] safeBags, PBECulture[] cultures) throws IOException
	{
		// создать список функций зашифрования
		List<PfxData<SafeBag>> bags = new ArrayList<PfxData<SafeBag>>(); 

		// для всех дочерних элементов
		for (int i = 0; i < safeBags.length; i++)
		{
			// указать функцию зашифрования
			PfxEncryptor encryptor = getItemEncryptor(safeBags[i].bagId().value(), cultures[i]); 
            
            // связать функцию шифрования с элементом
            bags.add(new PfxData<SafeBag>(safeBags[i], encryptor)); 
		}
		// добавить новый элемент
		addObjects(bags, (culture != null) ? new PfxEncryptor.Container(this, culture, null) : null); 
	}
	public final void addChild(PfxParentItem parent, 
        PBECulture culture, SafeBag safeBag) throws IOException
	{
    	// указать функцию зашифрования
		PfxEncryptor encryptor = getItemEncryptor(safeBag.bagId().value(), culture); 
        
		// добавить данные
		parent.addObject(new PfxData<SafeBag>(safeBag, encryptor)); 
	}
	///////////////////////////////////////////////////////////////////////
	// Найти элемент коллекции
	///////////////////////////////////////////////////////////////////////
	public final PfxSafeBag findObject(String type, byte[] id)
	{
		// найти требуемый элемент 
		PfxContainerSafeBag[] items = super.findObjects(new PfxFilter.Object(type, id));

		// проверить наличие элемента
		return items.length > 0 ? items[0].safeBag : null; 
	}
	///////////////////////////////////////////////////////////////////////
	// Управление запросами на сертификат
	///////////////////////////////////////////////////////////////////////
	public final PfxContainerSafeBag[] findCertificationRequests(PfxFilter callback)
	{
		// получить запросы на сертификат открытого ключа
		return findObjects(new PfxFilter.CertificationRequest(callback));
	}
	public final PfxSafeBag findCertificationRequest(byte[] keyID)
	{
		// указать фильтр поиска по идентификатору
		PfxFilter filter = new PfxFilter.Object(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SECRET, keyID);
 
		// получить запрос на сертификат открытого ключа
		PfxContainerSafeBag[] items = findCertificationRequests(filter); 

		// проверить наличие запроса на сертификат
		return items.length > 0 ? items[0].safeBag : null; 
	}
	///////////////////////////////////////////////////////////////////////
	// Управление сертификатами
	///////////////////////////////////////////////////////////////////////
	public final PfxContainerSafeBag[] findCertificates(PfxFilter callback)
	{
		// получить сертификаты открытого ключа
		return findObjects(new PfxFilter.Certificate(callback));
	}
	public final PfxSafeBag findCertificate(byte[] keyID)
	{
		// указать фильтр поиска по идентификатору
		PfxFilter filter = new PfxFilter.Object(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_CERT, keyID);

		// получить сертификаты открытого ключа
		PfxContainerSafeBag[] items = findCertificates(filter);

		// проверить наличие сертификата
		return items.length > 0 ? items[0].safeBag : null; 
	}
	///////////////////////////////////////////////////////////////////////
	// Управление личными ключами
	///////////////////////////////////////////////////////////////////////
	public final PfxContainerSafeBag[] findPrivateKeys(PfxFilter callback)
	{
		// получить личные ключи
		return findObjects(new PfxFilter.PrivateKey(callback));
	}
	public final PfxSafeBag findPrivateKey(byte[] keyID)
	{
		// получить закодированный личный ключ
		PfxSafeBag safeBag = findObject(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY, keyID);
        
        // вернуть закодированный личный ключ
        return (safeBag != null) ? safeBag : findObject(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SHROUNDED_KEY, keyID); 
	}
}
