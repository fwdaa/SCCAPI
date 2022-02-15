using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм вычисления имитовставки HMAC SHA2-512/t
    ///////////////////////////////////////////////////////////////////////////////
    public class HMAC_SHA2_512_T : HMAC
    {
        // число битов и алгоритм хэширования
        private int bits; private CAPI.Hash hashAlgorithm;

        // конструктор
        public HMAC_SHA2_512_T(CAPI.PKCS11.Applet applet, int bits) 
         
            // сохранить переданные параметры
            : this(applet, bits, (bits + 7) / 8) {} 
        
        // конструктор
        public HMAC_SHA2_512_T(CAPI.PKCS11.Applet applet, int bits, int macSize) 
                 
            // сохранить переданные параметры
            : base(applet, API.CKM_SHA512_T_HMAC, API.CKM_SHA512_T, macSize) 
        { 
            // указать параметры алгоритма
            this.bits = bits; Mechanism parameters = new Mechanism(API.CKM_SHA512_T, bits); 

            // создать алгоритм хэширования
            hashAlgorithm = Creator.CreateHash(applet.Provider, applet, parameters);
 
            // проверить поддержку алгоритма
            if (hashAlgorithm == null) throw new NotSupportedException(); 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            RefObject.Release(hashAlgorithm); base.OnDispose();
        }
        // получить алгоритм хэширования
        protected override CAPI.Hash GetHashAlgorithm() { return hashAlgorithm; } 

	    // параметры алгоритма
	    protected override Mechanism GetParameters(CAPI.PKCS11.Session session)
	    { 
		    // выделить память для параметров
		    return new Mechanism(API.CKM_SHA512_T_HMAC, bits); 
	    }
    }
}
