package aladdin.capi;

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Области использования ключа
/////////////////////////////////////////////////////////////////////////////////////////////////////////
// 1)  При создании ключа необходимо указать long (способ использования данного ключа). 
//     KeyUsage может быть любой битовой комбинацией из перечисления KeyUsage. На основании 
//     определенного алгоритма (специфического для каждого провайдера) по KeyUsage определяется 
//     способ идентификации данного ключа в контейнере: например, если контейнер – программный PKCS12, 
//     то все биты KeyUsage используются при идентификации; если контейнер – это контейнер CSP, 
//     то на основании KeyUsage определяется слот AT_KEYEXCHANGE или AT_SIGNATURE (см. далее). 
// 2)  При вызове последующих функций связанных с ключами (генерация запроса на сертификат, 
//     генерация сертификата) необходимо использовать KeyUsage, указанный при создании ключа. 
/////////////////////////////////////////////////////////////////////////////////////////////////////////
public class KeyUsage 
{ 
	public static final long DIGITAL_SIGNATURE      = aladdin.asn1.iso.pkix.ce.KeyUsage.DIGITAL_SIGNATURE    ;       
	public static final long NON_REPUDIATION        = aladdin.asn1.iso.pkix.ce.KeyUsage.NON_REPUDIATION      ;        
	public static final long KEY_ENCIPHERMENT       = aladdin.asn1.iso.pkix.ce.KeyUsage.KEY_ENCIPHERMENT     ;      
	public static final long DATA_ENCIPHERMENT		= aladdin.asn1.iso.pkix.ce.KeyUsage.DATA_ENCIPHERMENT    ;     
	public static final long KEY_AGREEMENT			= aladdin.asn1.iso.pkix.ce.KeyUsage.KEY_AGREEMENT        ;         
	public static final long CERTIFICATE_SIGNATURE	= aladdin.asn1.iso.pkix.ce.KeyUsage.CERTIFICATE_SIGNATURE; 
	public static final long CRL_SIGNATURE			= aladdin.asn1.iso.pkix.ce.KeyUsage.CRL_SIGNATURE        ;         
	public static final long ENCIPHER_ONLY			= aladdin.asn1.iso.pkix.ce.KeyUsage.ENCIPHER_ONLY        ;         
	public static final long DECIPHER_ONLY			= aladdin.asn1.iso.pkix.ce.KeyUsage.DECIPHER_ONLY        ;        

    // конструктор
    public KeyUsage(long value) { longValue = value; } 
    
    // получить значение
    public long value() { return longValue; } private final long longValue;
    
    // проверить наличие флагов
    public boolean isEmpty() { return longValue == 0; }
    
    // проверить наличие флага
    public boolean contains(long flag) { return (longValue & flag) != 0; }
    
    // проверить наличие одного из флагов
    public boolean containsAny(long keyUsage) { return contains(keyUsage); }

    // проверить наличие всех флагов
    public boolean containsAll(KeyUsage keyUsage) 
    { 
        // проверить наличие всех флагов
        return (longValue & keyUsage.value()) == keyUsage.value(); 
    }
    // объединение значений
    public static final KeyUsage NONE      = new KeyUsage(0);          
    //public static final KeyUsage KEYX_MASK = new KeyUsage(KEY_ENCIPHERMENT  | KEY_AGREEMENT);          
	//public static final KeyUsage SIGN_MASK = new KeyUsage(DIGITAL_SIGNATURE | CERTIFICATE_SIGNATURE | CRL_SIGNATURE | NON_REPUDIATION);        
    
    // выполнить логическое И
    public static final KeyUsage and(KeyUsage keyUsage1, KeyUsage keyUsage2)
    {
        // выполнить логическое И
        return new KeyUsage(keyUsage1.value() & keyUsage2.value()); 
    }
    // выполнить логическое ИЛИ
    public static final KeyUsage or(KeyUsage keyUsage1, KeyUsage keyUsage2)
    {
        // выполнить логическое ИЛИ
        return new KeyUsage(keyUsage1.value() | keyUsage2.value()); 
    }
    // выполнить логическое И с логическим отрицанием
    public static final KeyUsage and_not(KeyUsage keyUsage1, KeyUsage keyUsage2)
    {
        // выполнить логическое И
        return new KeyUsage(keyUsage1.value() & ~keyUsage2.value()); 
    }
}
