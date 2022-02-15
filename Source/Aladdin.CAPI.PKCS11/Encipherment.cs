using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////
	public abstract class Encipherment : CAPI.Encipherment
	{
		// используемое устройство
		private Applet applet;

		// конструктор
		protected Encipherment(Applet applet) 
		 
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

		// зашифровать данные
		public override byte[] Encrypt(IPublicKey publicKey, IRand rand, byte[] data)
        {
	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_ENCRYPT, API.CK_TRUE)
	        }; 
	        // открыть сеанс
	        using (Session session = applet.OpenSession(API.CKS_RO_PUBLIC_SESSION))
            {
	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, publicKey.Parameters);
 
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(parameters.AlgID); 
                 
	            // преобразовать тип ключа
	            SessionObject sessionKey = applet.Provider.ToSessionObject(
		            session, publicKey, info, keyAttributes
	            );
	            // инициализировать алгоритм
	            session.EncryptInit(parameters, sessionKey.Handle);

	            // зашифровать и закодировать данные
	            return session.Encrypt(data, 0, data.Length);
            }
        }
	}
}
