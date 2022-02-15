using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм обмена ключа PKCS11
	///////////////////////////////////////////////////////////////////////////////
	public abstract class TransportKeyWrap : CAPI.TransportKeyWrap
	{
		// используемое устройство
		private Applet applet;

		// конструктор
		protected TransportKeyWrap(Applet applet)
		 
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
		protected abstract Mechanism GetParameters(
            Session sesssion, IParameters parameters, IRand rand
        ); 
		// действия стороны-отправителя
		public override TransportKeyData Wrap(
            ASN1.ISO.AlgorithmIdentifier algorithmParameters, 
            IPublicKey publicKey, IRand rand, ISecretKey CEK)
        {
	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        applet.Provider.CreateAttribute(API.CKA_WRAP, API.CK_TRUE)
	        }; 
            // указать атрибуты защищаемого ключа
            Attribute[] attributes = applet.Provider.SecretKeyAttributes(CEK.KeyFactory, CEK.Length, true); 

	        // открыть сеанс /* TODO: */
	        using (Session session = applet.OpenSession(API.CKS_RW_USER_FUNCTIONS))
            {
	            // получить параметры алгоритма
	            Mechanism parameters = GetParameters(session, publicKey.Parameters, rand); 
                
                // получить информацию алгоритма
                MechanismInfo info = applet.GetAlgorithmInfo(parameters.AlgID); 

	            // преобразовать тип ключа
	            SessionObject sessionPublicKey = applet.Provider.ToSessionObject(
		            session, publicKey, info, keyAttributes
	            ); 
	            // преобразовать тип ключа
	            SessionObject sessionKey = applet.Provider.ToSessionObject(
		            session, CEK, attributes
                ); 
	            // зашифровать ключ
	            byte[] data = session.WrapKey(
		            parameters, sessionPublicKey.Handle, sessionKey.Handle
	            );
	            // вернуть зашифрованный ключ с параметрами обмена
	            return new TransportKeyData(algorithmParameters, data);
            }
        }
	}
}
