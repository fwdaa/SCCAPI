package aladdin.capi.pkcs12;
import aladdin.asn1.iso.pkcs.pkcs12.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////////
// Поиск требуемого объекта
///////////////////////////////////////////////////////////////////////////////
public abstract class PfxFilter
{
    // проверить соответствие объекта
	public abstract boolean isMatch(SafeBag safeBag, byte[] keyID) throws Exception;

    ///////////////////////////////////////////////////////////////////////////
    // Поиск объекта по типу и идентификатору
    ///////////////////////////////////////////////////////////////////////////
    public static class Object extends PfxFilter
    {
        // тип объекта и идентификатор
        private final String type; private final byte[] id; 

        // конструктор
        public Object(String type, byte[] id)
        {
            // сохранить переданные параметры
            this.type = type; this.id = id; 
        }
        // проверить соответствие объекта
        @Override public boolean isMatch(SafeBag safeBag, byte[] keyID)
        {
            // проверить тип элемента
            if (!safeBag.bagId().value().equals(type)) return false;

            // проверить совпадение идентификаторов
            return Arrays.equals(keyID, id); 
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Поиск запроса на сертификат
    ///////////////////////////////////////////////////////////////////////////
    public static class CertificationRequest extends PfxFilter
    {
        // конструктор
        public CertificationRequest(PfxFilter callback)

            // сохранить переданные параметры
            { this.callback = callback; } private final PfxFilter callback; 
            
        // проверить соответствие объекта
        @Override public boolean isMatch(SafeBag safeBag, byte[] keyID)
        {
			// проверить тип элемента
			if (!safeBag.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SECRET)) return false;
            try { 
                // извлечь содержимое элемента
                SecretBag secretBag = new SecretBag(safeBag.bagValue()); 

                // проверить идентификатор элемента
                if (!secretBag.secretTypeId().value().equals(aladdin.asn1.iso.pkcs.OID.PKCS10)) return false;

                // проверить критерий поиска
                return (callback == null || callback.isMatch(safeBag, keyID)); 
            }
            // обработать возможное исключение
            catch (Throwable e) { return false; }
        }            
    }
    ///////////////////////////////////////////////////////////////////////////
    // Поиск сертификата
    ///////////////////////////////////////////////////////////////////////////
    public static class Certificate extends PfxFilter
    {
        // конструктор
        public Certificate(PfxFilter callback)

            // сохранить переданные параметры
            { this.callback = callback; } private final PfxFilter callback; 
            
        // проверить соответствие объекта
        @Override public boolean isMatch(SafeBag safeBag, byte[] keyID)
        {
			// проверить тип сертификата
			if (!safeBag.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_CERT)) return false;

			// проверить критерий поиска
			try { return (callback == null || callback.isMatch(safeBag, keyID)); }
            
            // обработать возможное исключение
            catch (Throwable e) { return false; }
		}
    }
    ///////////////////////////////////////////////////////////////////////////
    // Поиск личного ключа
    ///////////////////////////////////////////////////////////////////////////
    public static class PrivateKey extends PfxFilter
    {
        // конструктор
        public PrivateKey(PfxFilter callback)

            // сохранить переданные параметры
            { this.callback = callback; } private final PfxFilter callback; 
            
        // проверить соответствие объекта
        @Override public boolean isMatch(SafeBag safeBag, byte[] keyID)
        {
			// проверить тип личного ключа
			if (!safeBag.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_SHROUNDED_KEY) && 
                !safeBag.bagId().value().equals(aladdin.asn1.iso.pkcs.pkcs12.OID.BT_KEY)) return false;

			// проверить критерий поиска
			try { return (callback == null || callback.isMatch(safeBag, keyID)); }

            // обработать возможное исключение
            catch (Throwable e) { return false; }
		}
    }
}
