using System;
using System.IO;

namespace Aladdin.ISO7816
{
	///////////////////////////////////////////////////////////////////////////
	// Тип объекта со способом кодирования
	///////////////////////////////////////////////////////////////////////////
    public class Tag : IEquatable<Tag>, IComparable<Tag>
    {
		// тип объекта заданного класса
		public static Tag Universal  (int value, ASN1.PC pc) { return new Tag(ASN1.Tag.Universal  (value), pc); }
		public static Tag Application(int value, ASN1.PC pc) { return new Tag(ASN1.Tag.Application(value), pc); } 
		public static Tag Context    (int value, ASN1.PC pc) { return new Tag(ASN1.Tag.Context    (value), pc); }
		public static Tag Private    (int value, ASN1.PC pc) { return new Tag(ASN1.Tag.Private    (value), pc); } 

		// сравнить два типа
		public static bool operator == (Tag A, Tag B) { return  A.Equals(B); }
		public static bool operator != (Tag A, Tag B) { return !A.Equals(B); }

		// сравнить два типа
        public static bool operator <= (Tag A, Tag B) { return A.CompareTo(B) <= 0; }
		public static bool operator >= (Tag A, Tag B) { return A.CompareTo(B) >= 0; }
		public static bool operator <  (Tag A, Tag B) { return A.CompareTo(B) <  0; }
		public static bool operator >  (Tag A, Tag B) { return A.CompareTo(B) >  0; }

        // тип, способ кодирования и закодированное представление
        public readonly ASN1.Tag AsnTag; public readonly ASN1.PC PC; public readonly byte[] Encoded; 

        // конструктор
        public Tag(ASN1.Tag asnTag, ASN1.PC pc)
        {
            // сохранить переданные параметры
            AsnTag = asnTag; PC = pc; Encoded = asnTag.Encode(pc); 
        }
        // конструктор
        private Tag(ASN1.Tag asnTag, ASN1.PC pc, byte[] encoded)
        {
            // сохранить переданные параметры
            AsnTag = asnTag; PC = pc; Encoded = encoded;
        }
        // класс объекта и тип объекта
        public ASN1.TagClass Class { get { return AsnTag.Class; }}
        public int           Value { get { return AsnTag.Value; }}

		// получить хэш-код объекта
		public override int GetHashCode() { return AsnTag.GetHashCode() ^ (int)PC; }

		// сравнить два объекта
		public override bool Equals(object other)
		{
			// сравнить два объекта
			return (other is Tag) ? Equals((Tag)other) : false;
		}
		// сравнить два объекта
		public bool Equals(Tag other)
		{
			// сравнить два объекта
			return AsnTag == other.AsnTag && PC == other.PC;
		}
		// сравнить два объекта
		public int CompareTo(Tag other)
		{
			// сравнить классы
			int cmp = (int)AsnTag.Class - (int)other.AsnTag.Class; if (cmp != 0) return cmp; 

            // сравнить способ кодирования
            cmp = (int)PC - (int)other.PC; if (cmp != 0) return cmp; 

            // сравнить значения
            return AsnTag.Value - other.AsnTag.Value; 
        }
        // раскодировать тип объекта со способом кодирования
        public static Tag Decode(byte[] encoded, int ofs, int length)
        {
            // проверить наличие данных
            if (length == 0) throw new InvalidDataException(); int value = 0; int cb = 1;

			// определить класс объекта 
			ASN1.TagClass tagClass = ASN1.TagClass.Universal; switch (encoded[ofs] >> 6)
			{
			// определить класс объекта 
			case 0x01: tagClass = ASN1.TagClass.Application;	break;
			case 0x02: tagClass = ASN1.TagClass.Context;		break;
			case 0x03: tagClass = ASN1.TagClass.Private;		break;
			}
			// определить способ кодирования объекта
			ASN1.PC pc = ((encoded[ofs] & 0x20) != 0) ? ASN1.PC.Constructed : ASN1.PC.Primitive;  

			// извлечь тип объекта
			if ((encoded[ofs] & 0x1F) < 0x1F) value = encoded[ofs] & 0x1F; 
			else {
                // проверить наличие данных
                if (length <= cb) throw new InvalidDataException();

				// для всех непоследних байтов типа
				while ((encoded[ofs + cb] & 0x80) == 0x80)
				{
					// скорректировать значение типа
					value <<= 7; value |= (encoded[ofs + cb++] & 0x7F);

                    // проверить наличие данных
                    if (length <= cb) throw new InvalidDataException();
				}
				// учесть последний байт типа
				value <<= 7; value |= encoded[ofs + cb++];    
			}
            // скопировать закодированное представление
            byte[] buffer = new byte[cb]; Array.Copy(encoded, ofs, buffer, 0, cb); 

            // вернуть раскодированный объект
            return new Tag(new ASN1.Tag(tagClass, value), pc, buffer); 
        }
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Межотраслевые информационные объекты
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        public static readonly Tag ObjectIdentifier                 = Tag.Universal  (0x06, ASN1.PC.Primitive  ); // идентификатор объекта
		public static readonly Tag CountryIndicator                 = Tag.Application(0x01, ASN1.PC.Primitive  ); // код страны и национальные данные                       +
		public static readonly Tag IssuerIndicator                  = Tag.Application(0x02, ASN1.PC.Primitive  ); // идентификационный номер эмитента                       +
		public static readonly Tag CardServiceData                  = Tag.Application(0x03, ASN1.PC.Primitive  ); // данные об услугах, предоставляемых картой              +
		public static readonly Tag InitialAccessData                = Tag.Application(0x04, ASN1.PC.Primitive  ); // исходные данные доступа                                +
		public static readonly Tag CardIssuerData                   = Tag.Application(0x05, ASN1.PC.Primitive  ); // данные эмитента                                        +
		public static readonly Tag PreIssuingData                   = Tag.Application(0x06, ASN1.PC.Primitive  ); // данные, предваряющие эмиссию карты                     +
		public static readonly Tag CardCapabilities                 = Tag.Application(0x07, ASN1.PC.Primitive  ); // функциональные возможности карты                       +
		public static readonly Tag LifeCycle                        = Tag.Application(0x08, ASN1.PC.Primitive  ); // информация о состоянии                                 +
		public static readonly Tag ApplicationFamily                = Tag.Application(0x09, ASN1.PC.Primitive  ); // идентификатор семейства приложений
		public static readonly Tag ExtendedHeaderList               = Tag.Application(0x0D, ASN1.PC.Primitive  ); // расширенный список заголовков                          +
		public static readonly Tag ApplicationIdentifier            = Tag.Application(0x0F, ASN1.PC.Primitive  ); // идентификатор приложения                               +
		public static readonly Tag ApplicationLabel                 = Tag.Application(0x10, ASN1.PC.Primitive  ); // метка приложения                                       +
		public static readonly Tag FileReference                    = Tag.Application(0x11, ASN1.PC.Primitive  ); // cсылка на файл                                         +
		public static readonly Tag CommandAPDU                      = Tag.Application(0x12, ASN1.PC.Primitive  ); // команда на выполнение                                  +
		public static readonly Tag DiscretionaryData                = Tag.Application(0x13, ASN1.PC.Primitive  ); // произвольные данные                                    +
		public static readonly Tag DataOffset                       = Tag.Application(0x14, ASN1.PC.Primitive  ); // информационный объект смещения
	    public static readonly Tag ApplicationTrack1                = Tag.Application(0x16, ASN1.PC.Primitive  ); // дорожка 1 (приложение)
	    public static readonly Tag ApplicationTrack2                = Tag.Application(0x17, ASN1.PC.Primitive  ); // дорожка 2 (приложение)
	    public static readonly Tag ApplicationTrack3                = Tag.Application(0x18, ASN1.PC.Primitive  ); // дорожка 3 (приложение)
		public static readonly Tag CardExpirationDate               = Tag.Application(0x19, ASN1.PC.Primitive  ); // дата истечения срока действия карты                    +
		public static readonly Tag PrimaryAccountNumber             = Tag.Application(0x1A, ASN1.PC.Primitive  ); // первичный идентификатор счета
		public static readonly Tag Name                             = Tag.Application(0x1B, ASN1.PC.Primitive  ); // имя
		public static readonly Tag TagList                          = Tag.Application(0x1C, ASN1.PC.Primitive  ); // cписок тегов                                           +
		public static readonly Tag HeaderList                       = Tag.Application(0x1D, ASN1.PC.Primitive  ); // cписок заголовков                                      +
		public static readonly Tag LoginData                        = Tag.Application(0x1E, ASN1.PC.Primitive  ); // данные логина
	    public static readonly Tag CardHolderName                   = Tag.Application(0x20, ASN1.PC.Primitive  ); // имя держателя карты
	    public static readonly Tag CardTrack1                       = Tag.Application(0x21, ASN1.PC.Primitive  ); // дорожка 1 (карта)
	    public static readonly Tag CardTrack2                       = Tag.Application(0x22, ASN1.PC.Primitive  ); // дорожка 2 (карта)
	    public static readonly Tag CardTrack3                       = Tag.Application(0x23, ASN1.PC.Primitive  ); // дорожка 3 (карта)
	    public static readonly Tag ApplicationExpirationDate        = Tag.Application(0x24, ASN1.PC.Primitive  ); // дата истечения срока действия приложения
	    public static readonly Tag ApplicationActivationDate        = Tag.Application(0x25, ASN1.PC.Primitive  ); // дата активации приложения
	    public static readonly Tag CardActivationDate               = Tag.Application(0x26, ASN1.PC.Primitive  ); // дата активации карты
	    public static readonly Tag TransmissionControl              = Tag.Application(0x27, ASN1.PC.Primitive  ); // управление обменом
	    public static readonly Tag CountryCode                      = Tag.Application(0x28, ASN1.PC.Primitive  ); // код страны
	    public static readonly Tag TransmissionProfile              = Tag.Application(0x29, ASN1.PC.Primitive  ); // профиль обмена
	    public static readonly Tag CurrencyCode                     = Tag.Application(0x2A, ASN1.PC.Primitive  ); // код валюты
	    public static readonly Tag Birthday                         = Tag.Application(0x2B, ASN1.PC.Primitive  ); // дата рождения
	    public static readonly Tag CardHolderCitizenship            = Tag.Application(0x2C, ASN1.PC.Primitive  ); // гражданство держателя карты
	    public static readonly Tag LanguagePreferences              = Tag.Application(0x2D, ASN1.PC.Primitive  ); // языковые предпочтения
	    public static readonly Tag CardHolderBiometricData          = Tag.Application(0x2E, ASN1.PC.Primitive  ); // биометрические данные держателя карты
	    public static readonly Tag PinUsageStrategy                 = Tag.Application(0x2F, ASN1.PC.Primitive  ); // стратегия использования PIN
	    public static readonly Tag ServiceCode                      = Tag.Application(0x30, ASN1.PC.Primitive  ); // сервисный код
	    public static readonly Tag TransactionCounter               = Tag.Application(0x32, ASN1.PC.Primitive  ); // счетчик транзакций
	    public static readonly Tag TransactionDate                  = Tag.Application(0x33, ASN1.PC.Primitive  ); // дата транзакции
	    public static readonly Tag CardOrdianalNumber               = Tag.Application(0x34, ASN1.PC.Primitive  ); // порядковый номер карты
	    public static readonly Tag Sex                              = Tag.Application(0x35, ASN1.PC.Primitive  ); // пол
	    public static readonly Tag CurrencyExponent                 = Tag.Application(0x36, ASN1.PC.Primitive  ); // экспонента валюты
	    public static readonly Tag StaticInternalAuthentication     = Tag.Application(0x37, ASN1.PC.Primitive  ); // cтатическая внутренняя аутентификация (одноступенчатая)
	    public static readonly Tag StaticInternalAuthentication1    = Tag.Application(0x38, ASN1.PC.Primitive  ); // статическая внутренняя аутентификация - первые ассоциированные данные
	    public static readonly Tag StaticInternalAuthentication2    = Tag.Application(0x39, ASN1.PC.Primitive  ); // статическая внутренняя аутентификация - вторые ассоциированные данные
	    public static readonly Tag DynamicInternalAuthentication    = Tag.Application(0x3A, ASN1.PC.Primitive  ); // динамическая внутренняя аутентификация
	    public static readonly Tag DynamicExternalAuthentication    = Tag.Application(0x3B, ASN1.PC.Primitive  ); // динамическая внешняя аутентификация
	    public static readonly Tag DynamicMutualAuthentication      = Tag.Application(0x3C, ASN1.PC.Primitive  ); // динамическая взаимная аутентификация
	    public static readonly Tag DigitalSignature                 = Tag.Application(0x3D, ASN1.PC.Primitive  ); // электронная цифровая подпись
	    public static readonly Tag CardHolderImage                  = Tag.Application(0x40, ASN1.PC.Primitive  ); // портретное изображение держателя карты
	    public static readonly Tag ElementList                      = Tag.Application(0x41, ASN1.PC.Primitive  ); // список элементов                                       +
	    public static readonly Tag Address                          = Tag.Application(0x42, ASN1.PC.Primitive  ); // адрес
	    public static readonly Tag CardHolderSignatureImage         = Tag.Application(0x43, ASN1.PC.Primitive  ); // изображение рукописной подписи держателя карты
	    public static readonly Tag ApplicationImage                 = Tag.Application(0x44, ASN1.PC.Primitive  ); // образ приложения
	    public static readonly Tag DisplyedMessage                  = Tag.Application(0x45, ASN1.PC.Primitive  ); // дисплейное сообщение
	    public static readonly Tag Timer                            = Tag.Application(0x46, ASN1.PC.Primitive  ); // таймер
	    public static readonly Tag MessageReference                 = Tag.Application(0x47, ASN1.PC.Primitive  ); // ссылка на сообщение
	    public static readonly Tag CardHolderPrivateKey             = Tag.Application(0x48, ASN1.PC.Primitive  ); // приватный ключ держателя карты
	    public static readonly Tag CertificatePublicKey             = Tag.Application(0x49, ASN1.PC.Primitive  ); // открытый ключ держателя карты
	    public static readonly Tag CertificationAuthorityPublicKey  = Tag.Application(0x4A, ASN1.PC.Primitive  ); // открытый ключ удостоверяющего центра
	    public static readonly Tag CertificateHolderAuthorization   = Tag.Application(0x4C, ASN1.PC.Primitive  ); // полномочия владельца сертификата
	    public static readonly Tag IntegratedCircuitManufacturerID  = Tag.Application(0x4D, ASN1.PC.Primitive  ); // идентификатор изготовителя интегральных схем
	    public static readonly Tag CertificateContent               = Tag.Application(0x4E, ASN1.PC.Primitive  ); // содержание сертификата
	    public static readonly Tag UniformResourceLocator           = Tag.Application(0x50, ASN1.PC.Primitive  ); // унифицированный указатель ресурса                      +
	    public static readonly Tag AnswerToReset                    = Tag.Application(0x51, ASN1.PC.Primitive  ); // ответ-на-восстановление                                +
	    public static readonly Tag HistoricalBytes                  = Tag.Application(0x52, ASN1.PC.Primitive  ); // байты предыстории                                      +
	    public static readonly Tag InternationalBankAccountNumber   = Tag.Application(0x53, ASN1.PC.Primitive  ); // международный номер банковского счета (IBAN)
	    public static readonly Tag BankIdentificationCode           = Tag.Application(0x54, ASN1.PC.Primitive  ); // идентификационный код банка (BIC)
	    public static readonly Tag CountryCodeAlpha2                = Tag.Application(0x55, ASN1.PC.Primitive  ); // код страны (формат alpha-2)
	    public static readonly Tag CountryCodeAlpha3                = Tag.Application(0x56, ASN1.PC.Primitive  ); // код страны (формат alpha-3)
	    public static readonly Tag AccountType                      = Tag.Application(0x57, ASN1.PC.Primitive  ); // вид счета
		public static readonly Tag ApplicationTemplate              = Tag.Application(0x01, ASN1.PC.Constructed); // шаблон приложения                                      +
		public static readonly Tag FileControlParameters            = Tag.Application(0x02, ASN1.PC.Constructed); // шаблон FCP
		public static readonly Tag Wrapper                          = Tag.Application(0x03, ASN1.PC.Constructed); // враппер                                                +
		public static readonly Tag FileManagementData               = Tag.Application(0x04, ASN1.PC.Constructed); // шаблон FMD                                             +
		public static readonly Tag CardHolderData                   = Tag.Application(0x05, ASN1.PC.Constructed); // данные, относящиеся к держателю карты
		public static readonly Tag CardData                         = Tag.Application(0x06, ASN1.PC.Constructed); // данные карты
		public static readonly Tag AuthenticationData               = Tag.Application(0x07, ASN1.PC.Constructed); // данные аутентификации
		public static readonly Tag UserRequirements                 = Tag.Application(0x08, ASN1.PC.Constructed); // особые требования пользователя
		public static readonly Tag LoginTemplate                    = Tag.Application(0x0A, ASN1.PC.Constructed); // шаблон логина
		public static readonly Tag QualifiedName                    = Tag.Application(0x0B, ASN1.PC.Constructed); // уточненное имя
		public static readonly Tag CardHolderImages                 = Tag.Application(0x0B, ASN1.PC.Constructed); // шаблон образов держателя карты
		public static readonly Tag ApplicationImageTemplate         = Tag.Application(0x0C, ASN1.PC.Constructed); // шаблон образа приложения
		public static readonly Tag ApplicationData                  = Tag.Application(0x0E, ASN1.PC.Constructed); // данные, относящиеся к приложению
		public static readonly Tag FileControlInformation           = Tag.Application(0x0F, ASN1.PC.Constructed); // шаблон FCI
		public static readonly Tag AuthorityTemplate0               = Tag.Application(0x10, ASN1.PC.Constructed); // шаблон для немежотраслевых информационных объектов     +
		public static readonly Tag AuthorityTemplate1               = Tag.Application(0x11, ASN1.PC.Constructed); // шаблон для немежотраслевых информационных объектов     +
		public static readonly Tag AuthorityTemplate2               = Tag.Application(0x12, ASN1.PC.Constructed); // шаблон для немежотраслевых информационных объектов     +
		public static readonly Tag DiscretionaryTemplate            = Tag.Application(0x13, ASN1.PC.Constructed); // произвольные информационные объекты                    +
		public static readonly Tag AuthorityTemplate4               = Tag.Application(0x14, ASN1.PC.Constructed); // шаблон для немежотраслевых информационных объектов     +
		public static readonly Tag AuthorityTemplate5               = Tag.Application(0x15, ASN1.PC.Constructed); // шаблон для немежотраслевых информационных объектов     +
		public static readonly Tag AuthorityTemplate6               = Tag.Application(0x16, ASN1.PC.Constructed); // шаблон для немежотраслевых информационных объектов     +
		public static readonly Tag AuthorityTemplate7               = Tag.Application(0x17, ASN1.PC.Constructed); // шаблон для немежотраслевых информационных объектов     +
		public static readonly Tag CompatibleTagScheme              = Tag.Application(0x18, ASN1.PC.Constructed); // источник распределения совместимых тегов               +
		public static readonly Tag CoexistentTagScheme              = Tag.Application(0x19, ASN1.PC.Constructed); // источник распределения сосуществующих тегов            +
		public static readonly Tag SecurityTemplate                 = Tag.Application(0x1A, ASN1.PC.Constructed); // шаблон обеспечения безопасности
		public static readonly Tag SecurityEnvironmentTemplate      = Tag.Application(0x1B, ASN1.PC.Constructed); // шаблон безопасной среды
		public static readonly Tag DynamicAuthenticationTemplate    = Tag.Application(0x1C, ASN1.PC.Constructed); // шаблон динамической аутентификации
		public static readonly Tag SecureMessaging                  = Tag.Application(0x1D, ASN1.PC.Constructed); // шаблон безопасного обмена сообщениями
		public static readonly Tag InterindustryTemplate            = Tag.Application(0x1E, ASN1.PC.Constructed); // шаблон для межотраслевых информационных объектов       +
    	public static readonly Tag DisplayControl                   = Tag.Application(0x20, ASN1.PC.Constructed); // управление отображением
	    public static readonly Tag CardHolderCertificate            = Tag.Application(0x21, ASN1.PC.Constructed); // сертификат держателя карты
	    public static readonly Tag CardHolderIncludedRequirements   = Tag.Application(0x22, ASN1.PC.Constructed); // требования держателя карты - включенные функции
	    public static readonly Tag CardHolderExcludedRequirements   = Tag.Application(0x23, ASN1.PC.Constructed); // требования держателя карты - исключенные функции
	    public static readonly Tag BiometricDataTemplate            = Tag.Application(0x24, ASN1.PC.Constructed); // шаблон биометрических данных
	    public static readonly Tag DigitalSignatureBlock            = Tag.Application(0x3D, ASN1.PC.Constructed); // блок электронной цифровой подписи
	    public static readonly Tag CardHolderPrivateKeyTemplate     = Tag.Application(0x48, ASN1.PC.Constructed); // шаблон приватного ключа держателя карты
	    public static readonly Tag CardHolderPublicKeyTemplate      = Tag.Application(0x49, ASN1.PC.Constructed); // шаблон открытого ключа держателя карты
	    public static readonly Tag CertificateContentTemplate       = Tag.Application(0x4E, ASN1.PC.Constructed); // шаблон содержимого сертификата
	    public static readonly Tag BiometricInformationTemplate     = Tag.Application(0x60, ASN1.PC.Constructed); // шаблон биометрической информации
	    public static readonly Tag BiometricInformationGroupTemplate= Tag.Application(0x60, ASN1.PC.Constructed); // шаблон группы шаблонов биометрической информации
/*
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Объекты шаблона FCP
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	    public static readonly Tag FCPFileContentSize               = Tag.Context(0x00, ASN1.PC.Primitive  ); // Number of data bytes in the file, excluding structural information
	    public static readonly Tag FCPFileTotalSize                 = Tag.Context(0x01, ASN1.PC.Primitive  ); // Number of data bytes in the file, including structural information if any
	    public static readonly Tag FCPFileDescriptor                = Tag.Context(0x02, ASN1.PC.Primitive  ); // File descriptor byte, data coding byte, maximum record size, number of records
	    public static readonly Tag FCPFileIdentifier                = Tag.Context(0x03, ASN1.PC.Primitive  ); // File identifier
	    public static readonly Tag FCPDedicatedFileName             = Tag.Context(0x04, ASN1.PC.Primitive  ); // DF name
	    public static readonly Tag FCPProprietaryData               = Tag.Context(0x05, ASN1.PC.Primitive  ); // Proprietary information not encoded in BER-TLV
	    public static readonly Tag FCPSecurityAttrProp              = Tag.Context(0x06, ASN1.PC.Primitive  ); // Security attribute in proprietary format 
	    public static readonly Tag FCPExtensionFileIdentifier       = Tag.Context(0x07, ASN1.PC.Primitive  ); // Identifier of an EF containing an extension of the file control information 
	    public static readonly Tag FCPShortFileIdentifier           = Tag.Context(0x08, ASN1.PC.Primitive  ); // Short EF identifier
	    public static readonly Tag FCPLifeCycle                     = Tag.Context(0x0A, ASN1.PC.Primitive  ); // Life cycle status byte 
	    public static readonly Tag FCPSecurityAttrExpanded          = Tag.Context(0x0B, ASN1.PC.Primitive  ); // Security attribute referencing the expanded format
	    public static readonly Tag FCPSecurityAttrCompact           = Tag.Context(0x0C, ASN1.PC.Primitive  ); // Security attribute in compact format 
	    public static readonly Tag FCPSecurityFileIdentifier        = Tag.Context(0x0D, ASN1.PC.Primitive  ); // Identifier of an EF containing security environment templates 
	    public static readonly Tag FCPChannelSecurityAttr           = Tag.Context(0x0E, ASN1.PC.Primitive  ); // Channel security attribute
	    public static readonly Tag FCPSecurityAttrs                 = Tag.Context(0x00, ASN1.PC.Constructed); // Security attribute template for data objects
	    public static readonly Tag FCPSecurityAttrsProp             = Tag.Context(0x01, ASN1.PC.Constructed); // Security attribute template in proprietary format
	    public static readonly Tag FCPFileMap                       = Tag.Context(0x02, ASN1.PC.Constructed); // Template consisting of one or more pairs of data objects: Short EF identifier (tag '88') - File reference (tag '51', L > 2)
	    public static readonly Tag FCPProprietaryTemplate           = Tag.Context(0x05, ASN1.PC.Constructed); // Proprietary information encoded in BER-TLV 
	    public static readonly Tag FCPSecurityAttrsExpanded         = Tag.Context(0x0B, ASN1.PC.Constructed); // Security attribute template in expanded format
	    public static readonly Tag FCPCryptoMechanismID             = Tag.Context(0x0C, ASN1.PC.Constructed); // Cryptographic mechanism identifier template
    
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Объекты шаблона безопасного обмена сообщениями
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	    public static readonly Tag SMPlainValue                     = Tag.Context(0x00, ASN1.PC.Primitive  ); // Plain value not encoded in BER-TLV
	    public static readonly Tag SMPlainValue1                    = Tag.Context(0x01, ASN1.PC.Primitive  ); // Plain value not encoded in BER-TLV
	    public static readonly Tag SMCryptogramSecureBER            = Tag.Context(0x02, ASN1.PC.Primitive  ); // Cryptogram (plain value encoded in BER-TLV and including SM data objects)
	    public static readonly Tag SMCryptogramSecureBER1           = Tag.Context(0x03, ASN1.PC.Primitive  ); // Cryptogram (plain value encoded in BER-TLV and including SM data objects)
	    public static readonly Tag SMCryptogramBER                  = Tag.Context(0x04, ASN1.PC.Primitive  ); // Cryptogram (plain value encoded in BER-TLV, but not including SM data objects
	    public static readonly Tag SMCryptogramBER1                 = Tag.Context(0x05, ASN1.PC.Primitive  ); // Cryptogram (plain value encoded in BER-TLV, but not including SM data objects
	    public static readonly Tag SMCryptogram                     = Tag.Context(0x06, ASN1.PC.Primitive  ); // Padding-content indicator byte followed by cryptogram (plain value not encoded in BER-TLV) 
	    public static readonly Tag SMCryptogram1                    = Tag.Context(0x07, ASN1.PC.Primitive  ); // Padding-content indicator byte followed by cryptogram (plain value not encoded in BER-TLV) 
	    public static readonly Tag SMCommandHeader                  = Tag.Context(0x09, ASN1.PC.Primitive  ); // Command header (CLA INS P1 P2, four bytes)
	    public static readonly Tag SMChecksum                       = Tag.Context(0x0E, ASN1.PC.Primitive  ); // Cryptographic checksum (at least four bytes)
	    public static readonly Tag SMHash                           = Tag.Context(0x10, ASN1.PC.Primitive  ); // Hash-code
	    public static readonly Tag SMHash1                          = Tag.Context(0x11, ASN1.PC.Primitive  ); // Hash-code
	    public static readonly Tag SMCertificate                    = Tag.Context(0x12, ASN1.PC.Primitive  ); // Certificate (data not encoded in BER-TLV)
	    public static readonly Tag SMCertificate1                   = Tag.Context(0x13, ASN1.PC.Primitive  ); // Certificate (data not encoded in BER-TLV)
	    public static readonly Tag SMSEID                           = Tag.Context(0x14, ASN1.PC.Primitive  ); // Security environment identifier (SEID byte)
	    public static readonly Tag SMSEID1                          = Tag.Context(0x15, ASN1.PC.Primitive  ); // Security environment identifier (SEID byte)
	    public static readonly Tag SMNE                             = Tag.Context(0x16, ASN1.PC.Primitive  ); // One or two bytes encoding Ne in the unsecured command-response pair (possibly empty)
	    public static readonly Tag SMNE1                            = Tag.Context(0x17, ASN1.PC.Primitive  ); // One or two bytes encoding Ne in the unsecured command-response pair (possibly empty)
	    public static readonly Tag SMSW                             = Tag.Context(0x19, ASN1.PC.Primitive  ); // Processing status (SW1-SW2, two bytes; possibly empty) 
	    public static readonly Tag SMSignInputValue                 = Tag.Context(0x1A, ASN1.PC.Primitive  ); // Input data element for the computation of a digital signature (the value field is signed)
	    public static readonly Tag SMSignInputValue1                = Tag.Context(0x1B, ASN1.PC.Primitive  ); // Input data element for the computation of a digital signature (the value field is signed)
	    public static readonly Tag SMPublicKey                      = Tag.Context(0x1C, ASN1.PC.Primitive  ); // Public key
	    public static readonly Tag SMPublicKey1                     = Tag.Context(0x1D, ASN1.PC.Primitive  ); // Public key
	    public static readonly Tag SMSignature                      = Tag.Context(0x1E, ASN1.PC.Primitive  ); // Digital signature
	    public static readonly Tag SMHashInputTemplate              = Tag.Context(0x00, ASN1.PC.Constructed); // Input template for the computation of a hash-code (the template is hashed)
	    public static readonly Tag SMHashInputTemplate1             = Tag.Context(0x01, ASN1.PC.Constructed); // Input template for the computation of a hash-code (the template is hashed)
	    public static readonly Tag SMChecksumTemplate               = Tag.Context(0x02, ASN1.PC.Constructed); // Input template for the verification of a cryptographic checksum (the template is included)
	    public static readonly Tag SMAuthenticationTemplate         = Tag.Context(0x04, ASN1.PC.Constructed); // Control reference template for authentication (AT)
	    public static readonly Tag SMAuthenticationTemplate1        = Tag.Context(0x05, ASN1.PC.Constructed); // Control reference template for authentication (AT)
	    public static readonly Tag SMKeyAgeementTemplate            = Tag.Context(0x06, ASN1.PC.Constructed); // Control reference template for key agreement (KAT) 
	    public static readonly Tag SMKeyAgeementTemplate1           = Tag.Context(0x07, ASN1.PC.Constructed); // Control reference template for key agreement (KAT) 
	    public static readonly Tag SMVerifyTemplate                 = Tag.Context(0x08, ASN1.PC.Constructed); // Input template for the verification of a digital signature (the template is signed) 
	    public static readonly Tag SMHashControlTemplate            = Tag.Context(0x0A, ASN1.PC.Constructed); // Control reference template for hash-code (HT)
	    public static readonly Tag SMHashControlTemplate1           = Tag.Context(0x0B, ASN1.PC.Constructed); // Control reference template for hash-code (HT)
	    public static readonly Tag SMSignInputValuesTemplate        = Tag.Context(0x0C, ASN1.PC.Constructed); // Input template for the computation of a digital signature (the concatenated value fields are signed) 
	    public static readonly Tag SMSignInputValuesTemplate1       = Tag.Context(0x0D, ASN1.PC.Constructed); // Input template for the computation of a digital signature (the concatenated value fields are signed) 
	    public static readonly Tag SMCertInputValuesTemplate        = Tag.Context(0x0E, ASN1.PC.Constructed); // Input template for the verification of a certificate (the concatenated value fields are certified)
	    public static readonly Tag SMCertInputValuesTemplate1       = Tag.Context(0x0F, ASN1.PC.Constructed); // Input template for the verification of a certificate (the concatenated value fields are certified)
	    public static readonly Tag SMPlainValueSecureBER            = Tag.Context(0x10, ASN1.PC.Constructed); // Plain value encoded in BER-TLV and including SM data objects
	    public static readonly Tag SMPlainValueSecureBER1           = Tag.Context(0x11, ASN1.PC.Constructed); // Plain value encoded in BER-TLV and including SM data objects
	    public static readonly Tag SMPlainValueBER                  = Tag.Context(0x12, ASN1.PC.Constructed); // Plain value encoded in BER-TLV, but not including SM data objects
	    public static readonly Tag SMPlainValueBER1                 = Tag.Context(0x13, ASN1.PC.Constructed); // Plain value encoded in BER-TLV, but not including SM data objects
	    public static readonly Tag SMChecksumControlTemplate        = Tag.Context(0x14, ASN1.PC.Constructed); // Control reference template for cryptographic checksum (CCT
	    public static readonly Tag SMChecksumControlTemplate1       = Tag.Context(0x15, ASN1.PC.Constructed); // Control reference template for cryptographic checksum (CCT
	    public static readonly Tag SMSignControlTemplate            = Tag.Context(0x16, ASN1.PC.Constructed); // Control reference template for digital signature (DST)
	    public static readonly Tag SMSignControlTemplate1           = Tag.Context(0x17, ASN1.PC.Constructed); // Control reference template for digital signature (DST)
	    public static readonly Tag SMConfidentialityTemplate        = Tag.Context(0x18, ASN1.PC.Constructed); // Control reference template for confidentiality (CT)
	    public static readonly Tag SMConfidentialityTemplate1       = Tag.Context(0x19, ASN1.PC.Constructed); // Control reference template for confidentiality (CT)
	    public static readonly Tag SMResponseDescriptor             = Tag.Context(0x1A, ASN1.PC.Constructed); // Response descriptor template
	    public static readonly Tag SMResponseDescriptor1            = Tag.Context(0x1B, ASN1.PC.Constructed); // Response descriptor template
	    public static readonly Tag SMSignInputTemplate              = Tag.Context(0x1C, ASN1.PC.Constructed); // Input template for the computation of a digital signature (the template is signed) 
	    public static readonly Tag SMSignInputTemplate1             = Tag.Context(0x1D, ASN1.PC.Constructed); // Input template for the computation of a digital signature (the template is signed) 
	    public static readonly Tag SMCertInputTemplate              = Tag.Context(0x1E, ASN1.PC.Constructed); // Input template for the verification of a certificate (the template is certified)
 */
    }
}
