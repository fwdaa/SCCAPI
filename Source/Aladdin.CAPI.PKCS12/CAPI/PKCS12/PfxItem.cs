using System;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Элемент контейнера PKCS12 
	///////////////////////////////////////////////////////////////////////////
	public abstract class PfxItem : RefObject, IEquatable<PfxItem>
	{
		// родительский узел и закодированное представление
		public abstract PfxParentItem	Parent  { get; } 
		public abstract ASN1.IEncodable Encoded { get; } 

		// признак наличия открытых и закрытых данных
		public abstract bool HasDecryptedItems { get; } 
		public abstract bool HasEncryptedItems { get; } 

		// расшифровать элемент
		protected internal abstract void Decrypt(PfxDecryptor decryptor);
        // изменить значение
        protected internal abstract void Change();

		// получить хэш-код объекта
		public override int GetHashCode() { return Encoded.GetHashCode(); }

		public override bool Equals(object obj)
		{
			// сравнить два объекта
			return (obj is PfxItem) ? Equals((PfxItem)obj) : false;  
		}
		public bool Equals(PfxItem obj)
		{
			// сравнить закодированные представления
			return Encoded.Equals(obj.Encoded); 
		}
	}
}
