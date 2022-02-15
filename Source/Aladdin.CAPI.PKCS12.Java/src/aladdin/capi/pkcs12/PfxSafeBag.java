package aladdin.capi.pkcs12;
import aladdin.asn1.*; 
import aladdin.capi.*; 
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Конечный элемент контейнера PKCS12 
///////////////////////////////////////////////////////////////////////////
public class PfxSafeBag extends PfxItem
{
	private final PfxParentItem     parent;		// родительский узел
    private PfxEncryptor            encryptor;  // функция зашифрования элемента
	private SafeBag                 encoded;	// закодированное представление
	private SafeBag                 decoded;	// раскодированное представление

	protected PfxSafeBag(PfxParentItem parent, 
        PfxData<SafeBag> decoded) throws IOException
	{  
		// установить значение элемента
		this.parent = parent; this.decoded = decoded.content; 
        
        // установить зашифрованное представление
        this.encryptor = decoded.encryptor; this.encoded = Pfx.encrypt(decoded); 
	} 
	protected PfxSafeBag(PfxParentItem parent, SafeBag encoded)
	{  
		// установить родительский узел
		this.parent = parent; this.encoded = encoded; encryptor = null; 
        
        // получить идентификатор элемента
        String bagID = encoded.bagId().value(); 
        
		// проверить наличие шифрования
		boolean encrypted = bagID.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SHROUNDED_KEY); 
        
		// при отсутствии шифрования
		decoded = (encrypted) ? null : encoded; 
	} 
	// закодированное представление
	@Override public PfxParentItem  parent () { return parent;  } 
	@Override public IEncodable     encoded() { return encoded; }

	// раскодированное представление
	public SafeBag decoded() { return decoded; } 

	// признак наличия открытых данных
	@Override public boolean hasDecryptedItems()
	{ 
        // признак наличия открытых данных
        return !hasEncryptedItems(); 
	} 
	// признак наличия закрытых данных
	@Override public boolean hasEncryptedItems()
	{ 
        // получить идентификатор элемента
        String bagID = encoded.bagId().value(); 
        
		// признак наличия зашифрования
		return bagID.equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SHROUNDED_KEY); 
	} 
	// расшифровать элемент
	@Override protected void decrypt(PfxDecryptor decryptor) throws IOException
	{
		// расшифровать данные
        PfxData<SafeBag> decrypted = Pfx.decrypt(encoded, decryptor); 

        // сохранить расшифрованные данные
		decoded = decrypted.content; encryptor = decrypted.encryptor; 
	}
    // изменить значение
    @Override protected void change() throws IOException
    {
        // проверить необходимость шифрования
        if (encryptor == null) return; 

        // связать значение со способом шифрования
        PfxData<SafeBag> decrypted = new PfxData<SafeBag>(decoded, encryptor); 

        // сохранить зашифрованное представление
        encoded = Pfx.encrypt(decrypted); parent.onItemsChange();
    }
	// установить значение элемента
	public void setValue(SafeBag value) throws IOException
	{
        // связать значение со способом шифрования
        PfxData<SafeBag> decrypted = new PfxData<SafeBag>(value, encryptor); 
        
		// сохранить зашифрованное представление
		encoded = Pfx.encrypt(decrypted); decoded = value; parent.onItemsChange();
	}
}
