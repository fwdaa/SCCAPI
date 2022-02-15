using System; 

namespace Aladdin.CAPI.PKCS12
{
    ///////////////////////////////////////////////////////////////////////////
	// Поиск требуемого объекта
    ///////////////////////////////////////////////////////////////////////////
	public abstract class PfxFilter
    {
        // проверить соответствие объекта
	    public abstract bool IsMatch(ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, byte[] keyID);

        ///////////////////////////////////////////////////////////////////////////
        // Поиск объекта по типу и идентификатору
        ///////////////////////////////////////////////////////////////////////////
        public class Object : PfxFilter
        {
            // тип объекта и идентификатор
            private string type; private byte[] id; 

            // конструктор
            public Object(string type, byte[] id)
            {
                // сохранить переданные параметры
                this.type = type; this.id = id; 
            }
            // проверить соответствие объекта
            public override bool IsMatch(
                ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, byte[] keyID)
            {
                // проверить тип элемента
                if (safeBag.BagId.Value != type) return false;

                // проверить совпадение идентификаторов
                return Arrays.Equals(keyID, id); 
            }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Поиск запроса на сертификат
        ///////////////////////////////////////////////////////////////////////////
        public class CertificationRequest : PfxFilter
        {
            // конструктор
            public CertificationRequest(PfxFilter callback)

                // сохранить переданные параметры
                { this.callback = callback; } private PfxFilter callback; 
            
            // проверить соответствие объекта
            public override bool IsMatch(
                ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, byte[] keyID)
            {
			    // проверить тип элемента
			    if (safeBag.BagId.Value != ASN1.ISO.PKCS.PKCS12.OID.bt_secret) return false;
                try { 
                    // извлечь содержимое элемента
                    ASN1.ISO.PKCS.PKCS12.SecretBag secretBag = new ASN1.ISO.PKCS.PKCS12.SecretBag(safeBag.BagValue); 

                    // проверить идентификатор элемента
                    if (secretBag.SecretTypeId.Value != ASN1.ISO.PKCS.OID.pkcs10) return false;

                    // проверить критерий поиска
                    return (callback == null || callback.IsMatch(safeBag, keyID)); 
                }
                // обработать возможное исключение
                catch (Exception) { return false; }
            }            
        }
        ///////////////////////////////////////////////////////////////////////////
        // Поиск сертификата
        ///////////////////////////////////////////////////////////////////////////
        public class Certificate : PfxFilter
        {
            // конструктор
            public Certificate(PfxFilter callback)

                // сохранить переданные параметры
                { this.callback = callback; } private PfxFilter callback; 
            
            // проверить соответствие объекта
            public override bool IsMatch(
                ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, byte[] keyID)
            {
			    // проверить тип сертификата
			    if (safeBag.BagId.Value != ASN1.ISO.PKCS.PKCS12.OID.bt_cert) return false;

			    // проверить критерий поиска
			    try { return (callback == null || callback.IsMatch(safeBag, keyID)); }
            
                // обработать возможное исключение
                catch (Exception) { return false; }
		    }
        }
        ///////////////////////////////////////////////////////////////////////////
        // Поиск личного ключа
        ///////////////////////////////////////////////////////////////////////////
        public class PrivateKey : PfxFilter
        {
            // конструктор
            public PrivateKey(PfxFilter callback)

                // сохранить переданные параметры
                { this.callback = callback; } private PfxFilter callback; 
            
            // проверить соответствие объекта
            public override bool IsMatch(
                ASN1.ISO.PKCS.PKCS12.SafeBag safeBag, byte[] keyID)
            {
			    // проверить тип личного ключа
			    if (safeBag.BagId.Value != ASN1.ISO.PKCS.PKCS12.OID.bt_shroudedKey && 
                    safeBag.BagId.Value != ASN1.ISO.PKCS.PKCS12.OID.bt_key) return false;

			    // проверить критерий поиска
			    try { return (callback == null || callback.IsMatch(safeBag, keyID)); }

                // обработать возможное исключение
                catch (Exception) { return false; }
		    }
        }
    }
}
