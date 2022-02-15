using System; 

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Конечный элемент контейнера PKCS12 
	///////////////////////////////////////////////////////////////////////////
	public class PfxSafeBag : PfxItem
	{
		private PfxParentItem					parent;		// родительский узел
		private PfxEncryptor					encryptor;	// функция зашифрования элемента
		private ASN1.ISO.PKCS.PKCS12.SafeBag	encoded;	// закодированное представление
		private ASN1.ISO.PKCS.PKCS12.SafeBag	decoded;	// раскодированное представление

		protected internal PfxSafeBag(PfxParentItem parent, PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag> decoded)
		{  
			// установить значение элемента
			this.parent = parent; this.decoded = decoded.Content; 
			
			// установить зашифрованное представление
			this.encryptor = decoded.Encryptor; this.encoded = Pfx.Encrypt(decoded); 
		} 
		protected internal PfxSafeBag(PfxParentItem parent, ASN1.ISO.PKCS.PKCS12.SafeBag encoded)
		{  
			// установить родительский узел
			this.parent = parent; this.encoded = encoded; encryptor = null; 

            // получить идентификатор элемента
            string bagID = encoded.BagId.Value; 
        
		    // проверить наличие шифрования
		    bool encrypted = (bagID == ASN1.ISO.PKCS.PKCS12.OID.bt_shroudedKey); 
        
			// установить расшифрованное представление
			decoded = (encrypted) ? null : encoded; 
		} 
		// закодированное/раскодированное представление
		public override PfxParentItem		Parent  { get { return parent;  } } 
		public override ASN1.IEncodable		Encoded { get { return encoded; } } 
		public ASN1.ISO.PKCS.PKCS12.SafeBag Decoded { get { return decoded; } } 

		// признак наличия открытых данных
		public override bool HasDecryptedItems { get { return !HasEncryptedItems; }}
		// признак наличия закрытых данных
		public override bool HasEncryptedItems { get 
		{ 
		    // проверить наличие шифрования
		    return encoded.BagId.Value == ASN1.ISO.PKCS.PKCS12.OID.bt_shroudedKey; 
		}}
		// расшифровать элемент
		protected internal override void Decrypt(PfxDecryptor decryptor)
		{
			// расшифровать данные
			PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag> decrypted = Pfx.Decrypt(encoded, decryptor); 

            // сохранить расшифрованные данные
            decoded = decrypted.Content; encryptor = decrypted.Encryptor; 
		}
        // изменить значение
        protected internal override void Change()
        {
            // проверить необходимость шифрования
            if (encryptor == null) return; 

            // связать значение со способом шифрования
            PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag> decrypted = 
                new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>(decoded, encryptor); 

			// сохранить зашифрованное представление
            encoded = Pfx.Encrypt(decrypted); parent.OnItemsChange();
        }
		// установить значение элемента
		public void SetValue(ASN1.ISO.PKCS.PKCS12.SafeBag value)
		{
            // связать значение со способом шифрования
            PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag> decrypted = 
                new PfxData<ASN1.ISO.PKCS.PKCS12.SafeBag>(value, encryptor); 

			// сохранить зашифрованное представление
            encoded = Pfx.Encrypt(decrypted); decoded = value; parent.OnItemsChange();
		}
	}
}
