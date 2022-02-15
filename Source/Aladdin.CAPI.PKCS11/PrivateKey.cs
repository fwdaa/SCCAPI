using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ PKCS11
	///////////////////////////////////////////////////////////////////////////
	public abstract class PrivateKey : CAPI.PrivateKey
	{
		// конструктор 
		protected PrivateKey(Factory factory, SecurityObject scope, string keyOID) 

			// сохранить переданные параметры
			: base(factory, scope, keyOID) {} 

		// создать сеансовый объект
		public virtual SessionObject ToSessionObject(Session session, Attribute[] attributes)
        {
			// получить значение атрибута
			Attribute tokenAttribute = KeyAttributes[API.CKA_TOKEN]; 
        
			// при отсутствии ключа на смарт-карте
			if (tokenAttribute == null || tokenAttribute.GetByte() == API.CK_FALSE)			
			{
				// создать сеансовый объект
				return session.CreateObject(KeyAttributes.Join(attributes).ToArray()); 
			}
			else {
				// выделить память для атрибутов поиска
				Attributes findAttributes = new Attributes(tokenAttribute, 

					// указать для поиска тип и идентификатор объекта
					KeyAttributes[API.CKA_CLASS], KeyAttributes[API.CKA_ID]
				);  
				// найти на смарт-карте ключ
				return session.FindObject(findAttributes.Join(attributes).ToArray()); 
			}
        } 
        // атрибуты ключа
        protected abstract Attributes KeyAttributes { get; } 
	}
}
