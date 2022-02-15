using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.Wrap
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования ключа AES
    ///////////////////////////////////////////////////////////////////////////
    public class AES : CAPI.PKCS11.KeyWrap
    {
        // конструктор
        public AES(CAPI.PKCS11.Applet applet) : this(applet, null) {}
    
        // конструктор
        public AES(CAPI.PKCS11.Applet applet, byte[] iv) : base(applet)
    
            // сохранить переданные параметры
            { this.iv = iv; } private byte[] iv; 
    
	    // параметры алгоритма
	    protected override Mechanism GetParameters(
            CAPI.PKCS11.Session sesssion, IRand rand)
        {
            // указать параметры алгоритма
            if (iv == null) return new Mechanism(API.CKM_AES_KEY_WRAP); 
        
            // указать параметры алгоритма
            return new Mechanism(API.CKM_AES_KEY_WRAP, iv); 
        }
    }
}
