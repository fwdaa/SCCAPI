package aladdin.capi.pkcs12; 
import aladdin.*; 
import aladdin.asn1.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Элемент контейнера PKCS12 
///////////////////////////////////////////////////////////////////////////
public abstract class PfxItem extends RefObject
{
	// родительский узел и закодированное представление
	public abstract PfxParentItem   parent ();
	public abstract IEncodable      encoded();

	// признак наличия открытых и закрытых данных
	public abstract boolean hasDecryptedItems(); 
	public abstract boolean hasEncryptedItems();

	// расшифровать элемент
	protected abstract void decrypt(PfxDecryptor decryptor) throws IOException;
    // изменить значение
    protected abstract void change() throws IOException;
  
	// получить хэш-код объекта
	@Override public int hashCode() { return encoded().hashCode(); }

    // сравнить объекты
    @Override public boolean equals(java.lang.Object obj)
	{
		// сравнить два объекта
		return (obj instanceof PfxItem) ? equals((PfxItem)obj) : false;  
	}
    // сравнить объекты
	public boolean equals(PfxItem obj)
	{
		// сравнить закодированные представления
		return encoded().equals(obj.encoded()); 
	}
}
