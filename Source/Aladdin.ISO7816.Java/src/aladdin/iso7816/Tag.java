package aladdin.iso7816;
import aladdin.asn1.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Известные типы объектов
///////////////////////////////////////////////////////////////////////////
public class Tag 
{
	// тип объекта заданного класса
	public static Tag universal  (int value, PC pc) { return new Tag(aladdin.asn1.Tag.universal  (value), pc); }
	public static Tag application(int value, PC pc) { return new Tag(aladdin.asn1.Tag.application(value), pc); } 
	public static Tag context    (int value, PC pc) { return new Tag(aladdin.asn1.Tag.context    (value), pc); }
	public static Tag privat     (int value, PC pc) { return new Tag(aladdin.asn1.Tag.privat     (value), pc); } 
    
    // тип, способ кодирования и закодированное представление
    public final aladdin.asn1.Tag asnTag; public final PC pc; public final byte[] encoded; 

    // конструктор
    public Tag(aladdin.asn1.Tag asnTag, PC pc)
    {
        // сохранить переданные параметры
        this.asnTag = asnTag; this.pc = pc; encoded = asnTag.encode(pc); 
    }
    // конструктор
    private Tag(aladdin.asn1.Tag asnTag, PC pc, byte[] encoded)
    {
        // сохранить переданные параметры
        this.asnTag = asnTag; this.pc = pc; this.encoded = encoded;
    }
    // класс объекта и тип объекта
    public final TagClass tagClass() { return asnTag.tagClass; }
    public final int      tagValue() { return asnTag.value;    }
    
    // получить хэш-код объекта
    @Override public int hashCode()
    {
    	// получить хэш-код объекта
    	return asnTag.hashCode() ^ pc.hashCode();
    }
    // сравнить два объекта
    public boolean equals(Tag other)
    {
    	// сравнить два объекта
    	return asnTag.equals(other.asnTag) && pc == other.pc;
    }
    // сравнить два объекта
    @Override public boolean equals(Object other)
    {
		// сравнить два объекта
		return (other instanceof Tag) ? equals((Tag)other) : false;
    }
    /////////////////////////////////////////////////////////////////////////////
    // Сравнить два объекта
    /////////////////////////////////////////////////////////////////////////////
    public static class Comparator implements java.util.Comparator<Tag>
    {
        // выполнить сравнение объектов
        @Override public int compare(Tag A, Tag B) { return A.compareTo(B); }
    }
    // сравнить объекты
    public int compareTo(Tag other)
    {
		// сравнить классы
		int cmp = asnTag.tagClass.value() - other.asnTag.tagClass.value(); if (cmp != 0) return cmp; 

        // сравнить способ кодирования
        cmp = pc.value() - other.pc.value(); if (cmp != 0) return cmp; 

        // сравнить значения
        return asnTag.value - other.asnTag.value; 
    }
    /////////////////////////////////////////////////////////////////////////////
    // Раскодировать тип объекта со способом кодирования
    /////////////////////////////////////////////////////////////////////////////
    public static Tag decode(byte[] encoded, int ofs, int length) throws IOException
    {
        // проверить наличие данных
        if (length == 0) throw new IOException(); int value = 0; int cb = 1;

        // определить класс объекта 
		TagClass tagClass = TagClass.UNIVERSAL; switch ((encoded[ofs] >>> 6) & 0x03)
		{
		// определить класс объекта 
		case 0x01: tagClass = TagClass.APPLICATION;	break;
		case 0x02: tagClass = TagClass.CONTEXT;		break;
		case 0x03: tagClass = TagClass.PRIVATE;		break;
		}
		// определить способ кодирования объекта
		PC pc = ((encoded[ofs] & 0x20) != 0) ? PC.CONSTRUCTED : PC.PRIMITIVE;  

		// извлечь тип объекта
		if ((encoded[ofs] & 0x1F) < 0x1F) value = encoded[ofs] & 0x1F; 
		else {
            // проверить наличие данных
            if (length <= cb) throw new IOException();

			// для всех непоследних байтов типа
			while ((encoded[ofs + cb] & 0x80) == 0x80)
			{
				// скорректировать значение типа
				value <<= 7; value |= (encoded[ofs + cb++] & 0x7F);

                // проверить наличие данных
                if (length <= cb) throw new IOException();
			}
			// учесть последний байт типа
			value <<= 7; value |= encoded[ofs + cb++] & 0xFF;    
		}
        // скопировать закодированное представление
        byte[] buffer = new byte[cb]; System.arraycopy(encoded, ofs, buffer, 0, cb); 

        // вернуть раскодированный объект
        return new Tag(new aladdin.asn1.Tag(tagClass, value), pc, buffer); 
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Межотраслевые информационные объекты
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    public static final Tag OBJECT_IDENTIFIER                    = Tag.universal  (0x06, PC.PRIMITIVE  ); // идентификатор объекта
	public static final Tag COUNTRY_INDICATOR                    = Tag.application(0x01, PC.PRIMITIVE  ); // код страны и национальные данные                         
	public static final Tag ISSUER_INDICATOR                     = Tag.application(0x02, PC.PRIMITIVE  ); // идентификационный номер эмитента                         
	public static final Tag CARD_SERVICE_DATA                    = Tag.application(0x03, PC.PRIMITIVE  ); // данные об услугах, предоставляемых картой                
	public static final Tag INITIAL_ACCESS_DATA                  = Tag.application(0x04, PC.PRIMITIVE  ); // исходные данные доступа                                  
	public static final Tag CARD_ISSUER_DATA                     = Tag.application(0x05, PC.PRIMITIVE  ); // данные эмитента                                          
	public static final Tag PRE_ISSUING_DATA                     = Tag.application(0x06, PC.PRIMITIVE  ); // данные, предваряющие эмиссию карты                       
	public static final Tag CARD_CAPABILITIES                    = Tag.application(0x07, PC.PRIMITIVE  ); // функциональные возможности карты                         
	public static final Tag LIFE_CYCLE                           = Tag.application(0x08, PC.PRIMITIVE  ); // информация о состоянии                                   
	public static final Tag APPLICATION_FAMILY                   = Tag.application(0x09, PC.PRIMITIVE  ); // идентификатор семейства приложений                       
	public static final Tag EXTENDED_HEADER_LIST                 = Tag.application(0x0D, PC.PRIMITIVE  ); // расширенный список заголовков                            +
	public static final Tag APPLICATION_IDENTIFIER               = Tag.application(0x0F, PC.PRIMITIVE  ); // идентификатор приложения                                 +
	public static final Tag APPLICATION_LABEL                    = Tag.application(0x10, PC.PRIMITIVE  ); // метка приложения                                         +
	public static final Tag FILE_REFERENCE                       = Tag.application(0x11, PC.PRIMITIVE  ); // cсылка на файл                                           +
	public static final Tag COMMAND_APDU                         = Tag.application(0x12, PC.PRIMITIVE  ); // команда на выполнение                                    +
	public static final Tag DISCRETIONARY_DATA                   = Tag.application(0x13, PC.PRIMITIVE  ); // произвольные данные                                      +
	public static final Tag DATA_OFFSET                          = Tag.application(0x14, PC.PRIMITIVE  ); // информационный объект смещения
	public static final Tag APPLICATION_TRACK_1                  = Tag.application(0x16, PC.PRIMITIVE  ); // дорожка 1 (приложение)
	public static final Tag APPLICATION_TRACK_2                  = Tag.application(0x17, PC.PRIMITIVE  ); // дорожка 2 (приложение)
	public static final Tag APPLICATION_TRACK_3                  = Tag.application(0x18, PC.PRIMITIVE  ); // дорожка 3 (приложение)
	public static final Tag CARD_EXPIRATION_DATE                 = Tag.application(0x19, PC.PRIMITIVE  ); // дата истечения срока действия карты                      +
	public static final Tag PRIMARY_ACCOUNT_NUMBER               = Tag.application(0x1A, PC.PRIMITIVE  ); // первичный идентификатор счета
	public static final Tag NAME                                 = Tag.application(0x1B, PC.PRIMITIVE  ); // имя  
	public static final Tag TAG_LIST                             = Tag.application(0x1C, PC.PRIMITIVE  ); // cписок тегов                                             +
	public static final Tag HEADER_LIST                          = Tag.application(0x1D, PC.PRIMITIVE  ); // cписок заголовков                                        +
	public static final Tag LOGIN_DATA                           = Tag.application(0x1E, PC.PRIMITIVE  ); // данные логина                                            
	public static final Tag CARD_HOLDER_NAME                     = Tag.application(0x20, PC.PRIMITIVE  ); // имя держателя карты
	public static final Tag CARD_TRACK_1                         = Tag.application(0x21, PC.PRIMITIVE  ); // дорожка 1 (карта)
	public static final Tag CARD_TRACK_2                         = Tag.application(0x22, PC.PRIMITIVE  ); // дорожка 2 (карта)
	public static final Tag CARD_TRACK_3                         = Tag.application(0x23, PC.PRIMITIVE  ); // дорожка 3 (карта)
	public static final Tag APPLICATION_EXPIRATION_DATE          = Tag.application(0x24, PC.PRIMITIVE  ); // дата истечения срока действия приложения
	public static final Tag APPLICATION_ACTIVATION_DATE          = Tag.application(0x25, PC.PRIMITIVE  ); // дата активации приложения
	public static final Tag CARD_ACTIVATION_DATE                 = Tag.application(0x26, PC.PRIMITIVE  ); // дата активации карты
	public static final Tag TRANSMISSION_CONTROL                 = Tag.application(0x27, PC.PRIMITIVE  ); // управление обменом
	public static final Tag COUNTRY_CODE                         = Tag.application(0x28, PC.PRIMITIVE  ); // код страны
	public static final Tag TRANSMISSION_PROFILE                 = Tag.application(0x29, PC.PRIMITIVE  ); // профиль обмена
	public static final Tag CURRENCY_CODE                        = Tag.application(0x2A, PC.PRIMITIVE  ); // код валюты
	public static final Tag BIRTHDAY                             = Tag.application(0x2B, PC.PRIMITIVE  ); // дата рождения
	public static final Tag CARD_HOLDER_CITIZENSHIP              = Tag.application(0x2C, PC.PRIMITIVE  ); // гражданство держателя карты
	public static final Tag LANGUAGE_PREFERENCES                 = Tag.application(0x2D, PC.PRIMITIVE  ); // языковые предпочтения
	public static final Tag CARD_HOLDER_BIOMETRIC_DATA           = Tag.application(0x2E, PC.PRIMITIVE  ); // биометрические данные держателя карты
	public static final Tag PIN_USAGE_STRATEGY                   = Tag.application(0x2F, PC.PRIMITIVE  ); // стратегия использования PIN
	public static final Tag SERVICE_CODE                         = Tag.application(0x30, PC.PRIMITIVE  ); // сервисный код
	public static final Tag TRANSACTION_COUNTER                  = Tag.application(0x32, PC.PRIMITIVE  ); // счетчик транзакций
	public static final Tag TRANSACTION_DATE                     = Tag.application(0x33, PC.PRIMITIVE  ); // дата транзакции
	public static final Tag CARD_ORDINAL_NUMBER                  = Tag.application(0x34, PC.PRIMITIVE  ); // порядковый номер карты
	public static final Tag SEX                                  = Tag.application(0x35, PC.PRIMITIVE  ); // пол
	public static final Tag CURRENCY_EXPONENT                    = Tag.application(0x36, PC.PRIMITIVE  ); // экспонента валюты
	public static final Tag STATIC_INTERNAL_AUTHENTICATION       = Tag.application(0x37, PC.PRIMITIVE  ); // cтатическая внутренняя аутентификация (одноступенчатая)
	public static final Tag STATIC_INTERNAL_AUTHENTICATION_1     = Tag.application(0x38, PC.PRIMITIVE  ); // статическая внутренняя аутентификация - первые ассоциированные данные
	public static final Tag STATIC_INTERNAL_AUTHENTICATION_2     = Tag.application(0x39, PC.PRIMITIVE  ); // статическая внутренняя аутентификация - вторые ассоциированные данные
	public static final Tag DYNAMIC_INTERNAL_AUTHENTICATION      = Tag.application(0x3A, PC.PRIMITIVE  ); // динамическая внутренняя аутентификация
	public static final Tag DYNAMIC_EXTERNAL_AUTHENTICATION      = Tag.application(0x3B, PC.PRIMITIVE  ); // динамическая внешняя аутентификация
	public static final Tag DYNAMIC_MUTUAL_AUTHENTICATION        = Tag.application(0x3C, PC.PRIMITIVE  ); // динамическая взаимная аутентификация
	public static final Tag DIGITAL_SIGNATURE                    = Tag.application(0x3D, PC.PRIMITIVE  ); // электронная цифровая подпись
	public static final Tag CARD_HOLDER_IMAGE                    = Tag.application(0x40, PC.PRIMITIVE  ); // портретное изображение держателя карты
	public static final Tag ELEMENT_LIST                         = Tag.application(0x41, PC.PRIMITIVE  ); // список элементов                                         +
	public static final Tag ADDRESS                              = Tag.application(0x42, PC.PRIMITIVE  ); // адрес
	public static final Tag CARD_HOLDER_SIGNATURE_IMAGE          = Tag.application(0x43, PC.PRIMITIVE  ); // изображение рукописной подписи держателя карты
	public static final Tag APPLICATION_IMAGE                    = Tag.application(0x44, PC.PRIMITIVE  ); // образ приложения
	public static final Tag DISPLAYED_MESSAGE                    = Tag.application(0x45, PC.PRIMITIVE  ); // дисплейное сообщение
	public static final Tag TIMER                                = Tag.application(0x46, PC.PRIMITIVE  ); // таймер
	public static final Tag MESSAGE_REFERENCE                    = Tag.application(0x47, PC.PRIMITIVE  ); // ссылка на сообщение
	public static final Tag CARD_HOLDER_PRIVATE_KEY              = Tag.application(0x48, PC.PRIMITIVE  ); // приватный ключ держателя карты
	public static final Tag CERTIFICATE_PUBLIC_KEY               = Tag.application(0x49, PC.PRIMITIVE  ); // открытый ключ держателя карты
	public static final Tag CERTIFICATION_AUTHORITY_PUBLIC_KEY   = Tag.application(0x4A, PC.PRIMITIVE  ); // открытый ключ удостоверяющего центра
	public static final Tag CERTIFICATE_HOLDER_AUTHORIZATION     = Tag.application(0x4C, PC.PRIMITIVE  ); // авторизация владельца сертификата
	public static final Tag INTEGRATED_CIRCUIT_MANUFACTURER_ID   = Tag.application(0x4D, PC.PRIMITIVE  ); // идентификатор изготовителя интегральных схем
	public static final Tag CERTIFICATE_CONTENT                  = Tag.application(0x4E, PC.PRIMITIVE  ); // содержание сертификата
	public static final Tag UNIFORM_RESOURCE_LOCATOR             = Tag.application(0x50, PC.PRIMITIVE  ); // унифицированный указатель ресурса                        +
	public static final Tag ANSWER_TO_RESET                      = Tag.application(0x51, PC.PRIMITIVE  ); // ответ-на-восстановление                                  +
	public static final Tag HISTORICAL_BYTES                     = Tag.application(0x52, PC.PRIMITIVE  ); // байты предыстории                                        +
	public static final Tag INTERNATIONAL_BANK_ACCOUNT_NUMBER    = Tag.application(0x53, PC.PRIMITIVE  ); // международный номер банковского счета (IBAN)
	public static final Tag BANK_IDENTIFICATION_CODE             = Tag.application(0x54, PC.PRIMITIVE  ); // идентификационный код банка (BIC)
	public static final Tag COUNTRY_CODE_ALPHA2                  = Tag.application(0x55, PC.PRIMITIVE  ); // код страны (формат alpha-2)
	public static final Tag COUNTRY_CODE_ALPHA3                  = Tag.application(0x56, PC.PRIMITIVE  ); // код страны (формат alpha-3)
	public static final Tag ACCOUNT_TYPE                         = Tag.application(0x57, PC.PRIMITIVE  ); // вид счета
	public static final Tag APPLICATION_TEMPLATE                 = Tag.application(0x01, PC.CONSTRUCTED); // шаблон приложения                                        +
	public static final Tag FILE_CONTROL_PARAMETERS              = Tag.application(0x02, PC.CONSTRUCTED); // шаблон FCP
	public static final Tag WRAPPER                              = Tag.application(0x03, PC.CONSTRUCTED); // враппер                                                  +
	public static final Tag FILE_MANAGEMENT_DATA                 = Tag.application(0x04, PC.CONSTRUCTED); // шаблон FMD                                               +
	public static final Tag CARD_HOLDER_DATA                     = Tag.application(0x05, PC.CONSTRUCTED); // данные, относящиеся к держателю карты
	public static final Tag CARD_DATA                            = Tag.application(0x06, PC.CONSTRUCTED); // данные карты
	public static final Tag AUTHENTICATION_DATA                  = Tag.application(0x07, PC.CONSTRUCTED); // данные аутентификации
	public static final Tag USER_REQUIREMENTS                    = Tag.application(0x08, PC.CONSTRUCTED); // особые требования пользователя
	public static final Tag LOGIN_TEMPLATE                       = Tag.application(0x0A, PC.CONSTRUCTED); // шаблон логина
	public static final Tag QUALIFIED_NAME                       = Tag.application(0x0B, PC.CONSTRUCTED); // уточненное имя
	public static final Tag CARD_HOLDER_IMAGES                   = Tag.application(0x0B, PC.CONSTRUCTED); // шаблон образов держателя карты
	public static final Tag APPLICATION_IMAGE_TEMPLATE           = Tag.application(0x0C, PC.CONSTRUCTED); // шаблон образа приложения
	public static final Tag APPLICATION_DATA                     = Tag.application(0x0E, PC.CONSTRUCTED); // данные, относящиеся к приложению
	public static final Tag FILE_CONTROL_INFORMATION             = Tag.application(0x0F, PC.CONSTRUCTED); // шаблон FCI
	public static final Tag AUTHORITY_TEMPLATE0                  = Tag.application(0x10, PC.CONSTRUCTED); // шаблон для немежотраслевых информационных объектов       +
	public static final Tag AUTHORITY_TEMPLATE1                  = Tag.application(0x11, PC.CONSTRUCTED); // шаблон для немежотраслевых информационных объектов       +
	public static final Tag AUTHORITY_TEMPLATE2                  = Tag.application(0x12, PC.CONSTRUCTED); // шаблон для немежотраслевых информационных объектов       +
	public static final Tag DISCRETIONARY_TEMPLATE               = Tag.application(0x13, PC.CONSTRUCTED); // произвольные информационные объекты                      +
	public static final Tag AUTHORITY_TEMPLATE4                  = Tag.application(0x14, PC.CONSTRUCTED); // шаблон для немежотраслевых информационных объектов       +
	public static final Tag AUTHORITY_TEMPLATE5                  = Tag.application(0x15, PC.CONSTRUCTED); // шаблон для немежотраслевых информационных объектов       +
	public static final Tag AUTHORITY_TEMPLATE6                  = Tag.application(0x16, PC.CONSTRUCTED); // шаблон для немежотраслевых информационных объектов       +
	public static final Tag AUTHORITY_TEMPLATE7                  = Tag.application(0x17, PC.CONSTRUCTED); // шаблон для немежотраслевых информационных объектов       +
	public static final Tag COMPATIBLE_TAG_SCHEME                = Tag.application(0x18, PC.CONSTRUCTED); // источник распределения совместимых тегов                 +
	public static final Tag COEXISTENT_TAG_SCHEME                = Tag.application(0x19, PC.CONSTRUCTED); // источник распределения сосуществующих тегов              +
	public static final Tag SECURITY_TEMPLATE                    = Tag.application(0x1A, PC.CONSTRUCTED); // шаблон обеспечения безопасности
	public static final Tag SECURITY_ENVIRONMENT_TEMPLATE        = Tag.application(0x1B, PC.CONSTRUCTED); // шаблон безопасной среды
	public static final Tag DYNAMIC_AUTHENTICATION_TEMPLATE      = Tag.application(0x1C, PC.CONSTRUCTED); // шаблон динамической аутентификации
	public static final Tag SECURE_MESSAGING                     = Tag.application(0x1D, PC.CONSTRUCTED); // шаблон безопасного обмена сообщениями
	public static final Tag INTERINDUSTRY_TEMPLATE               = Tag.application(0x1E, PC.CONSTRUCTED); // шаблон для межотраслевых информационных объектов         +
	public static final Tag DISPLAY_CONTROL                      = Tag.application(0x20, PC.CONSTRUCTED); // управление отображением
	public static final Tag CARD_HOLDER_CERTIFICATE              = Tag.application(0x21, PC.CONSTRUCTED); // сертификат держателя карты
	public static final Tag CARD_HOLDER_INCLUDED_REQUIREMENTS    = Tag.application(0x22, PC.CONSTRUCTED); // требования держателя карты - включенные функции
	public static final Tag CARD_HOLDER_EXCLUDED_REQUIREMENTS    = Tag.application(0x23, PC.CONSTRUCTED); // требования держателя карты - исключенные функции
	public static final Tag BIOMERTIC_DATA_TEMPLATE              = Tag.application(0x24, PC.CONSTRUCTED); // шаблон биометрических данных
	public static final Tag DIGITAL_SIGNATURE_BLOCK              = Tag.application(0x3D, PC.CONSTRUCTED); // блок электронной цифровой подписи
	public static final Tag CARD_HOLDER_PRIVATE_KEY_TEMPLATE     = Tag.application(0x48, PC.CONSTRUCTED); // шаблон приватного ключа держателя карты
	public static final Tag CARD_HOLDER_PUBLIC_KEY_TEMPLATE      = Tag.application(0x49, PC.CONSTRUCTED); // шаблон открытого ключа держателя карты
	public static final Tag CERTIFICATE_CONTENT_TEMPLATE         = Tag.application(0x4E, PC.CONSTRUCTED); // шаблон содержимого сертификата
	public static final Tag BIOMETRIC_INFORMATION_TEMPLATE       = Tag.application(0x60, PC.CONSTRUCTED); // шаблон биометрической информации
	public static final Tag BIOMETRIC_INFORMATION_GROUP_TEMPLATE = Tag.application(0x60, PC.CONSTRUCTED); // шаблон группы шаблонов биометрической информации
/*    
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Объекты шаблона FCP
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public static final Tag FCP_FILE_CONTENT_SIZE         = Tag.context(0x00, PC.PRIMITIVE  ); // Number of data bytes in the file, excluding structural information
	public static final Tag FCP_FILE_TOTAL_SIZE           = Tag.context(0x01, PC.PRIMITIVE  ); // Number of data bytes in the file, including structural information if any
	public static final Tag FCP_FILE_DESCRIPTOR           = Tag.context(0x02, PC.PRIMITIVE  ); // File descriptor byte, data coding byte, maximum record size, number of records
	public static final Tag FCP_FILE_IDENTIFIER           = Tag.context(0x03, PC.PRIMITIVE  ); // File identifier
	public static final Tag FCP_DEDICATED_FILE_NAME       = Tag.context(0x04, PC.PRIMITIVE  ); // DF name
	public static final Tag FCP_PROPRIETARY_DATA          = Tag.context(0x05, PC.PRIMITIVE  ); // Proprietary information not encoded in BER-TLV
	public static final Tag FCP_SECURITY_ATTR_PROP        = Tag.context(0x06, PC.PRIMITIVE  ); // Security attribute in proprietary format 
	public static final Tag FCP_EXTENSION_FILE_IDENTIFIER = Tag.context(0x07, PC.PRIMITIVE  ); // Identifier of an EF containing an extension of the file control information 
	public static final Tag FCP_SHORT_FILE_IDENTIFIER     = Tag.context(0x08, PC.PRIMITIVE  ); // Short EF identifier
	public static final Tag FCP_LIFE_CYCLE                = Tag.context(0x0A, PC.PRIMITIVE  ); // Life cycle status byte 
	public static final Tag FCP_SECURITY_ATTR_EXPANDED    = Tag.context(0x0B, PC.PRIMITIVE  ); // Security attribute referencing the expanded format
	public static final Tag FCP_SECURITY_ATTR_COMPACT     = Tag.context(0x0C, PC.PRIMITIVE  ); // Security attribute in compact format 
	public static final Tag FCP_SECURITY_FILE_IDENTIFIER  = Tag.context(0x0D, PC.PRIMITIVE  ); // Identifier of an EF containing security environment templates 
	public static final Tag FCP_CHANNEL_SECURITY_ATTR     = Tag.context(0x0E, PC.PRIMITIVE  ); // Channel security attribute
	public static final Tag FCP_SECURITY_ATTRS            = Tag.context(0x00, PC.CONSTRUCTED); // Security attribute template for data objects
	public static final Tag FCP_SECURITY_ATTRS_PROP       = Tag.context(0x01, PC.CONSTRUCTED); // Security attribute template in proprietary format
	public static final Tag FCP_FILES_MAP                 = Tag.context(0x02, PC.CONSTRUCTED); // Template consisting of one or more pairs of data objects: Short EF identifier (tag '88') - File reference (tag '51', L > 2)
	public static final Tag FCP_PROPRIETARY_TEMPLATE      = Tag.context(0x05, PC.CONSTRUCTED); // Proprietary information encoded in BER-TLV 
	public static final Tag FCP_SECURITY_ATTRS_EXPANDED   = Tag.context(0x0B, PC.CONSTRUCTED); // Security attribute template in expanded format
	public static final Tag FCP_CRYPTO_MECHANISM_ID       = Tag.context(0x0C, PC.CONSTRUCTED); // Cryptographic mechanism identifier template
    
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Объекты шаблона безопасного обмена сообщениями
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public static final Tag SM_PLAIN_VALUE                   = Tag.context(0x00, PC.PRIMITIVE  ); // Plain value not encoded in BER-TLV
	public static final Tag SM_PLAIN_VALUE1                  = Tag.context(0x01, PC.PRIMITIVE  ); // Plain value not encoded in BER-TLV
	public static final Tag SM_CRYPTOGRAM_SECURE_BER         = Tag.context(0x02, PC.PRIMITIVE  ); // Cryptogram (plain value encoded in BER-TLV and including SM data objects)
	public static final Tag SM_CRYPTOGRAM_SECURE_BER1        = Tag.context(0x03, PC.PRIMITIVE  ); // Cryptogram (plain value encoded in BER-TLV and including SM data objects)
	public static final Tag SM_CRYPTOGRAM_BER                = Tag.context(0x04, PC.PRIMITIVE  ); // Cryptogram (plain value encoded in BER-TLV, but not including SM data objects
	public static final Tag SM_CRYPTOGRAM_BER1               = Tag.context(0x05, PC.PRIMITIVE  ); // Cryptogram (plain value encoded in BER-TLV, but not including SM data objects
	public static final Tag SM_CRYPTOGRAM                    = Tag.context(0x06, PC.PRIMITIVE  ); // Padding-content indicator byte followed by cryptogram (plain value not encoded in BER-TLV) 
	public static final Tag SM_CRYPTOGRAM1                   = Tag.context(0x07, PC.PRIMITIVE  ); // Padding-content indicator byte followed by cryptogram (plain value not encoded in BER-TLV) 
	public static final Tag SM_COMMAND_HEADER                = Tag.context(0x09, PC.PRIMITIVE  ); // Command header (CLA INS P1 P2, four bytes)
	public static final Tag SM_CHECKSUM                      = Tag.context(0x0E, PC.PRIMITIVE  ); // Cryptographic checksum (at least four bytes)
	public static final Tag SM_HASH                          = Tag.context(0x10, PC.PRIMITIVE  ); // Hash-code
	public static final Tag SM_HASH1                         = Tag.context(0x11, PC.PRIMITIVE  ); // Hash-code
	public static final Tag SM_CERTIFICATE                   = Tag.context(0x12, PC.PRIMITIVE  ); // Certificate (data not encoded in BER-TLV)
	public static final Tag SM_CERTIFICATE1                  = Tag.context(0x13, PC.PRIMITIVE  ); // Certificate (data not encoded in BER-TLV)
	public static final Tag SM_SEID                          = Tag.context(0x14, PC.PRIMITIVE  ); // Security environment identifier (SEID byte)
	public static final Tag SM_SEID1                         = Tag.context(0x15, PC.PRIMITIVE  ); // Security environment identifier (SEID byte)
	public static final Tag SM_NE                            = Tag.context(0x16, PC.PRIMITIVE  ); // One or two bytes encoding Ne in the unsecured command-response pair (possibly empty)
	public static final Tag SM_NE_ODD                        = Tag.context(0x17, PC.PRIMITIVE  ); // One or two bytes encoding Ne in the unsecured command-response pair (possibly empty)
	public static final Tag SM_SW                            = Tag.context(0x19, PC.PRIMITIVE  ); // Processing status (SW1-SW2, two bytes; possibly empty) 
	public static final Tag SM_SIGN_INPUT_VALUE              = Tag.context(0x1A, PC.PRIMITIVE  ); // Input data element for the computation of a digital signature (the value field is signed)
	public static final Tag SM_SIGN_INPUT_VALUE1             = Tag.context(0x1B, PC.PRIMITIVE  ); // Input data element for the computation of a digital signature (the value field is signed)
	public static final Tag SM_PUBLIC_KEY                    = Tag.context(0x1C, PC.PRIMITIVE  ); // Public key
	public static final Tag SM_PUBLIC_KEY1                   = Tag.context(0x1D, PC.PRIMITIVE  ); // Public key
	public static final Tag SM_SIGNATURE                     = Tag.context(0x1E, PC.PRIMITIVE  ); // Digital signature
	public static final Tag SM_HASH_INPUT_TEMPLATE           = Tag.context(0x00, PC.CONSTRUCTED); // Input template for the computation of a hash-code (the template is hashed)
	public static final Tag SM_HASH_INPUT_TEMPLATE1          = Tag.context(0x01, PC.CONSTRUCTED); // Input template for the computation of a hash-code (the template is hashed)
	public static final Tag SM_CHECKSUM_TEMPLATE             = Tag.context(0x02, PC.CONSTRUCTED); // Input template for the verification of a cryptographic checksum (the template is included)
	public static final Tag SM_AUTHENTICATION_CRT            = Tag.context(0x04, PC.CONSTRUCTED); // Control reference template for authentication (AT)
	public static final Tag SM_AUTHENTICATION_CRT1           = Tag.context(0x05, PC.CONSTRUCTED); // Control reference template for authentication (AT)
	public static final Tag SM_KEY_AGREEMENT_CRT             = Tag.context(0x06, PC.CONSTRUCTED); // Control reference template for key agreement (KAT) 
	public static final Tag SM_KEY_AGREEMENT_CRT1            = Tag.context(0x07, PC.CONSTRUCTED); // Control reference template for key agreement (KAT) 
	public static final Tag SM_VERIFY_TEMPLATE               = Tag.context(0x08, PC.CONSTRUCTED); // Input template for the verification of a digital signature (the template is signed) 
	public static final Tag SM_HASH_CRT                      = Tag.context(0x0A, PC.CONSTRUCTED); // Control reference template for hash-code (HT)
	public static final Tag SM_HASH_CRT1                     = Tag.context(0x0B, PC.CONSTRUCTED); // Control reference template for hash-code (HT)
	public static final Tag SM_SIGN_INPUT_VALUES_TEMPLATE    = Tag.context(0x0C, PC.CONSTRUCTED); // Input template for the computation of a digital signature (the concatenated value fields are signed) 
	public static final Tag SM_SIGN_INPUT_VALUES_TEMPLATE1   = Tag.context(0x0D, PC.CONSTRUCTED); // Input template for the computation of a digital signature (the concatenated value fields are signed) 
	public static final Tag SM_CERT_INPUT_VALUES_TEMPLATE    = Tag.context(0x0E, PC.CONSTRUCTED); // Input template for the verification of a certificate (the concatenated value fields are certified)
	public static final Tag SM_CERT_INPUT_VALUES_TEMPLATE1   = Tag.context(0x0F, PC.CONSTRUCTED); // Input template for the verification of a certificate (the concatenated value fields are certified)
	public static final Tag SM_PLAIN_VALUE_SECURE_BER        = Tag.context(0x10, PC.CONSTRUCTED); // Plain value encoded in BER-TLV and including SM data objects
	public static final Tag SM_PLAIN_VALUE_SECURE_BER1       = Tag.context(0x11, PC.CONSTRUCTED); // Plain value encoded in BER-TLV and including SM data objects
	public static final Tag SM_PLAIN_VALUE_BER               = Tag.context(0x12, PC.CONSTRUCTED); // Plain value encoded in BER-TLV, but not including SM data objects
	public static final Tag SM_PLAIN_VALUE_BER1              = Tag.context(0x13, PC.CONSTRUCTED); // Plain value encoded in BER-TLV, but not including SM data objects
	public static final Tag SM_CHECKSUM_CRT                  = Tag.context(0x14, PC.CONSTRUCTED); // Control reference template for cryptographic checksum (CCT
	public static final Tag SM_CHECKSUM_CRT1                 = Tag.context(0x15, PC.CONSTRUCTED); // Control reference template for cryptographic checksum (CCT
	public static final Tag SM_SIGN_CRT                      = Tag.context(0x16, PC.CONSTRUCTED); // Control reference template for digital signature (DST)
	public static final Tag SM_SIGN_CRT1                     = Tag.context(0x17, PC.CONSTRUCTED); // Control reference template for digital signature (DST)
	public static final Tag SM_CONF_CRT                      = Tag.context(0x18, PC.CONSTRUCTED); // Control reference template for confidentiality (CT)
	public static final Tag SM_CONF_CRT1                     = Tag.context(0x19, PC.CONSTRUCTED); // Control reference template for confidentiality (CT)
	public static final Tag SM_RESPONSE_DESCRIPTOR           = Tag.context(0x1A, PC.CONSTRUCTED); // Response descriptor template
	public static final Tag SM_RESPONSE_DESCRIPTOR1          = Tag.context(0x1B, PC.CONSTRUCTED); // Response descriptor template
	public static final Tag SM_SIGN_INPUT_TEMPLATE           = Tag.context(0x1C, PC.CONSTRUCTED); // Input template for the computation of a digital signature (the template is signed) 
	public static final Tag SM_SIGN_INPUT_TEMPLATE1          = Tag.context(0x1D, PC.CONSTRUCTED); // Input template for the computation of a digital signature (the template is signed) 
	public static final Tag SM_CERT_INPUT_TEMPLATE           = Tag.context(0x1E, PC.CONSTRUCTED); // Input template for the verification of a certificate (the template is certified)
*/   
}