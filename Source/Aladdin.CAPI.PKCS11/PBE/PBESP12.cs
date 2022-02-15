namespace Aladdin.CAPI.PKCS11.PBE
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования по паролю PKCS12
    ///////////////////////////////////////////////////////////////////////////
    public abstract class PBESP12 : CAPI.Cipher
    {
        // физическое устройство и идентификатор алгоритма
        private CAPI.PKCS11.Applet applet; private ulong algID; 
        // алгоритм наследования ключа и тип ключа
        private CAPI.KeyDerive keyDerive; private SecretKeyFactory keyFactory; 
    
	    // конструктор
	    protected PBESP12(CAPI.PKCS11.Applet applet, 
            ulong algID, byte[] salt, int iterations, SecretKeyFactory keyFactory)
        { 
		    // сохранить переданные параметры
		    this.applet = RefObject.AddRef(applet); this.algID = algID; 
        
            // создать алгоритм наследования ключа
            this.keyDerive = new PBKDFP12(this, salt, iterations); this.keyFactory = keyFactory; 
        }
        // деструктор
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            keyDerive.Dispose(); RefObject.Release(applet); base.OnDispose();
        } 
	    // используемое устройство 
	    public CAPI.PKCS11.Applet Applet { get { return applet; }}
    
        // идентификатор алгоритма
        public ulong AlgID { get { return algID; }}
    
	    // создать алгоритм шифрования
	    protected abstract CAPI.Cipher CreateCipher(byte[] iv); 
	    // размер ключа
	    protected abstract int KeyLength { get; }  
    
	    // алгоритм зашифрования данных
        protected override Transform CreateEncryption(ISecretKey password)
	    {
            // выделить память для синхропосылки
            byte[] iv = new byte[8];  
        
		    // наследовать ключ и вектор инициализации по паролю
            using (ISecretKey key = keyDerive.DeriveKey(password, iv, keyFactory, KeyLength)) 
            {
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(iv))
                {
                    // вернуть преобразование зашифрования
                    return cipher.CreateEncryption(key, PaddingMode.PKCS5); 
                }
            }
	    }
	    // алгоритм расшифрования данных
        protected override Transform CreateDecryption(ISecretKey password)
	    {
            // выделить память для синхропосылки
            byte[] iv = new byte[8];  
        
		    // наследовать ключ и вектор инициализации по паролю
            using (ISecretKey key = keyDerive.DeriveKey(password, iv, keyFactory, KeyLength)) 
            {
                // создать алгоритм шифрования
                using (CAPI.Cipher cipher = CreateCipher(iv))
                {
                    // вернуть преобразование расшифрования
                    return cipher.CreateDecryption(key, PaddingMode.PKCS5); 
                }
            }
	    }
	    // атрибуты ключа
	    public virtual Attribute[] GetKeyAttributes() 
        {   
            // атрибуты ключа
            return applet.Provider.SecretKeyAttributes(keyFactory, KeyLength, false); 
        } 
    }
}
