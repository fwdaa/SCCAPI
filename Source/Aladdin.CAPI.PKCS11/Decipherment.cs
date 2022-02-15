using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////
	public abstract class Decipherment : CAPI.Decipherment
	{
		// используемое устройство
		private Applet applet;

		// конструктор
		protected Decipherment(Applet applet) 
		 
			// сохранить переданные параметры
			{ this.applet = RefObject.AddRef(applet); } 

        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(applet); base.OnDispose(); 
        }
		// используемое устройство
		protected Applet Applet { get { return applet; }} 
        
		// параметры алгоритма
		protected abstract Mechanism GetParameters(Session sesssion, IParameters parameters);  

		// расшифровать данные
		public override byte[] Decrypt(IPrivateKey privateKey, byte[] data)
        {
	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_DECRYPT, API.CK_TRUE)
	        }; 
	        // открыть сеанс
	        using (Session session = applet.OpenSession(API.CKS_RO_USER_FUNCTIONS))
            {
	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, privateKey.Parameters); 
                
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(parameters.AlgID); 

	            // преобразовать тип ключа
	            SessionObject sessionKey = applet.Provider.ToSessionObject(
		            session, privateKey, info, keyAttributes
	            );
	            // инициализировать алгоритм
	            session.DecryptInit(parameters, sessionKey.Handle);

	            // расшифровать данные
	            return session.Decrypt(data, 0, data.Length);
            }
        }
	}
}
