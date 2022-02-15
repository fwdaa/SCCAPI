using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.ANSI.PKCS11.MAC
{
    ///////////////////////////////////////////////////////////////////////////////
    // Алгоритм вычисления имитовставки HMAC
    ///////////////////////////////////////////////////////////////////////////////
    public class HMAC_GENERAL : CAPI.PKCS11.MAC.HMAC
    {
        // идентификаторы HMAC-алгоритма и алгоритм хэширования
        private ulong hmacID; private CAPI.Hash hashAlgorithm;

        // конструктор
	    public HMAC_GENERAL(CAPI.PKCS11.Applet applet, ulong hmacID, ulong hashID, int macSize) 
            
            // сохранить переданные параметры
            : this(applet, hmacID, hashID, API.CKK_GENERIC_SECRET, macSize) {} 

        // конструктор
	    public HMAC_GENERAL(CAPI.PKCS11.Applet applet, ulong hmacID, ulong hashID, ulong keyType, int macSize) 
            
            // сохранить переданные параметры
            : base(applet, keyType, macSize) 
        { 
            // указать параметры алгоритма
            this.hmacID = hmacID; Mechanism parameters = new Mechanism(hashID); 

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
		    return new Mechanism(hmacID, MacSize); 
	    }
    }
}
