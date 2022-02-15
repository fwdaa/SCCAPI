using System;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.GOST.PKCS11.Sign.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////
    // Проверка подписи данных ГОСТ Р 34.10-2001
    ///////////////////////////////////////////////////////////////////////
    public class VerifyData2001 : GOST.Sign.GOSTR3410.VerifyData2001
    {
        // используемый провайдер и апплет
        private CAPI.PKCS11.Provider provider; private CAPI.PKCS11.Applet applet; 
    
        // конструктор
        public VerifyData2001(CAPI.PKCS11.Provider provider, CAPI.PKCS11.Applet applet, 
            CAPI.VerifyHash verifyAlgorithm) : base(verifyAlgorithm) 
        { 
            // сохранить переданные параметры
            this.provider = RefObject.AddRef(provider); 
            this.applet   = RefObject.AddRef(applet  ); 
        }
        // деструктор
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(applet); RefObject.Release(provider); base.OnDispose();
        }
        // получить алгоритм хэширования
        protected override CAPI.Hash CreateHashAlgorithm(string hashOID)
        {
            // извлечь идентификатор таблицы подстановок
            ASN1.ObjectIdentifier oid = new ASN1.ObjectIdentifier(hashOID); 
        
            // указать параметры алгоритма
            Mechanism mechanism = new Mechanism(API.CKM_GOSTR3411, oid.Encoded); 
            
            // создать алгоритм хэширования
            CAPI.Hash hashAlgorithm = Creator.CreateHash(provider, applet, mechanism); 
        
            // проверить поддержку алгоритма
            if (hashAlgorithm == null) throw new NotSupportedException(); return hashAlgorithm; 
        }
    }
}
