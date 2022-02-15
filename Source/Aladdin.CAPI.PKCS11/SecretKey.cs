using System;
using System.Diagnostics.CodeAnalysis;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Ключ PKCS11
	///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class SecretKey : RefObject, ISecretKey
	{
		// считыватель, тип и атрибуты ключа
		private Applet applet; private SecretKeyFactory keyFactory; private Attributes keyAttributes; 

		// конструктор
		public SecretKey(Applet applet, SecretKeyFactory keyFactory, Attributes keyAttributes)
        {
	        // сохранить переданные параметры
	        this.applet = RefObject.AddRef(applet); 

	        // сохранить атрибуты ключа
	        this.keyFactory = keyFactory; this.keyAttributes = keyAttributes; 
        }
        // деструктор
        protected override void OnDispose() 
        {
	        // проверить необходимость удаления
	        if (applet == null) { base.OnDispose(); return; }
	        try { 
		        // открыть сеанс
		        using (Session session = applet.OpenSession(API.CKS_RW_USER_FUNCTIONS)) 
                {
		            // получить ссылку на объект
		            SessionObject sessionObject = ToSessionObject(session, null); 

		            // удалить объект на токене
		            session.DestroyObject(sessionObject); 
                }
	        }
	        // освободить выделенные ресурсы
	        catch {} RefObject.Release(applet); base.OnDispose();
        } 
		// тип ключа
		public SecretKeyFactory KeyFactory { get { return keyFactory; }}
		// размер ключа
		public int Length { get { return Value.Length; }}

		// значение ключа
		public virtual byte[] Value { get 
        {
			// получить требуемый атрибут
			Aladdin.PKCS11.Attribute attribute = keyAttributes[API.CKA_VALUE]; 

			// вернуть значение атрибута
			return (attribute != null) ? attribute.Value : null; 
		}}
		// создать сеансовый объект
		public virtual SessionObject ToSessionObject(Session session, Attribute[] attributes)
		{
			// получить значение атрибута
			Attribute tokenAttribute = keyAttributes[API.CKA_TOKEN]; 
        
			// при отсутствии ключа на смарт-карте
			if (tokenAttribute == null || tokenAttribute.GetByte() == API.CK_FALSE)			
			{
				// создать сеансовый объект
				return session.CreateObject(keyAttributes.Join(attributes).ToArray()); 
			}
			else {
				// выделить память для атрибутов поиска
				Attributes findAttributes = new Attributes(tokenAttribute, 

					// указать для поиска тип и идентификатор объекта
					keyAttributes[API.CKA_CLASS], keyAttributes[API.CKA_ID]
				);  
				// найти на смарт-карте ключ
				return session.FindObject(findAttributes.Join(attributes).ToArray()); 
			}
		}
	}; 
}
