using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Алгоритм зашифрования данных 
	///////////////////////////////////////////////////////////////////////////////
	public class Encryption : Transform
	{
		private Cipher		cipher;		// алгоритм шифрования
		private PaddingMode	padding;	// режим дополнения
		private ISecretKey		key;		// ключ шифрования
		private Session	    session;	// используемый сеанс

		// конструктор
		public Encryption(Cipher cipher, PaddingMode padding, ISecretKey key)
        {
	        // сохранить переданные параметры
	        this.cipher = RefObject.AddRef(cipher); this.padding = padding;

	        // инициализировать параметры
	        this.key = RefObject.AddRef(key); session = null; 
        }
        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            if (session != null) session.Dispose(); 

            // освободить выделенные ресурсы
            RefObject.Release(key); RefObject.Release(cipher); base.OnDispose(); 
        }
		// размер блока
		public override int BlockSize { get { return cipher.BlockSize; }}
		// режим дополнения
		public override PaddingMode Padding { get { return padding; }}

		// инициализировать алгоритм
		public override void Init()
        {
	        // указать дополнительные атрибуты ключа
	        Attribute[] keyAttributes = new Attribute[] {
		        cipher.Applet.Provider.CreateAttribute(API.CKA_ENCRYPT, API.CK_TRUE)
	        }; 
	        // получить атрибуты ключа
	        keyAttributes = Attribute.Join(keyAttributes, cipher.GetKeyAttributes(key.Length));  

			// при необходимости закрыть старый сеанс
			if (session != null) { session.Dispose(); session = null; } 

	        // открыть новый сеанс
	        session = cipher.Applet.OpenSession(API.CKS_RO_PUBLIC_SESSION);
	        try {
		        // получить параметры алгоритма
		        Mechanism parameters = cipher.GetParameters(session); 

		        // преобразовать тип ключа
		        SessionObject sessionKey = cipher.Applet.Provider.ToSessionObject(
                    session, key, keyAttributes
                ); 
		        // инициализировать алгоритм
		        session.EncryptInit(parameters, sessionKey.Handle);
	        }
			// при ошибке закрыть сеанс 
	        catch { session.Dispose(); session = null; throw; } 
        }
		// преобразовать данные
		public override int Update(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
        {
	        // проверить наличие данных
	        if (dataLen == 0) return 0; 

	        // зашифровать данные
	        return session.EncryptUpdate(data, dataOff, dataLen, buf, bufOff); 
        }
		// завершить преобразование
		public override int Finish(byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff)
        {
	        // зашифровать данные
	        int total = session.EncryptUpdate(data, dataOff, dataLen, buf, bufOff); 

	        // завершить зашифрование данных
	        total += session.EncryptFinal(buf, bufOff + total); 

            // закрыть сеанс
            session.Dispose(); session = null; return total; 
        } 
	} 
}
