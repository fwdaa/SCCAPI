#include "StdAfx.h"
#include "ProApplet.h"
#include "NativeAPI.h"

#define CK_Win32
#include "cryptoki/cryptoki.h"
#include "cryptoki/eTPkcs11.h"
#include "TracePKCS11.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ProFormat.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Вычислить хэш-значение MD5 от ключа
///////////////////////////////////////////////////////////////////////////////
static array<BYTE>^ HashStartKey(Aladdin::PKCS11::Module^ module, 
    UInt64 hSession, array<BYTE>^ buffer)
{
	// выделить буфер требуемого размера
	array<BYTE>^ digest = gcnew array<BYTE>(16); 

    // создать алгоритм хэширования
	module->DigestInit(hSession, gcnew Aladdin::PKCS11::Mechanism(CKM_MD5));

	// выполнить алгоритм хэширования
	module->DigestUpdate(hSession, buffer, 0, buffer->Length); 

    // завершить алгоритм хэширования
	CK_ULONG ulSize = module->DigestFinal(hSession, digest, (CK_ULONG)0); 

	// вернуть хэш-значение
	Array::Resize(digest, ulSize); return digest;  
}

///////////////////////////////////////////////////////////////////////////////
// Проверить наличие дополнительных возможностей
///////////////////////////////////////////////////////////////////////////////
static CK_BBOOL IsFeatureSupported(Aladdin::PKCS11::Module^ module, 
	CK_SLOT_ID nSlotID, CK_ULONG feature)
{
	using namespace Aladdin; 

    // указать атрибуты объекта для поиска
	array<PKCS11::Attribute^>^ tokenAttributes = gcnew array<PKCS11::Attribute^> { 
		module->CreateAttribute(CKA_CLASS          , (UInt64)CKO_HW_FEATURE    ), 
		module->CreateAttribute(CKA_HW_FEATURE_TYPE, (UInt64)ETCKH_TOKEN_OBJECT)
	};  
    // открыть криптографический сеанс
	UInt64 hSession = module->OpenSession(nSlotID, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    try { 
        // найти объекты с указанными атрибутами
		array<UInt64>^ objs = module->FindObjects(hSession, tokenAttributes);

		// проверить наличие только одного объекта
		if (objs->Length == 0) return CK_FALSE; if (objs->Length > 1)
		{
			// при ошибке выбросить исключение
			throw gcnew PKCS11::Exception(CKR_TEMPLATE_INCOMPLETE); 
		} 
		// указать требуемый атрибут
		tokenAttributes = gcnew array<PKCS11::Attribute^> {
			module->CreateAttribute(feature, (CK_BBOOL)CK_FALSE)
		}; 
		// найти требуемый атрибут
		tokenAttributes = module->GetAttributes(hSession, objs[0], tokenAttributes);

		// вернуть признак поддержки
		return tokenAttributes[0]->Value[0] != 0;  
    }
    // закрыть открытый сеанс
    finally { module->CloseSession(hSession); }
}

///////////////////////////////////////////////////////////////////////////////
// Основная функция форматирования
///////////////////////////////////////////////////////////////////////////////
static void PerformFormat(Aladdin::PKCS11::Module^ module, String^ adminPIN, 
    Aladdin::CAPI::SCard::APDU::Pro::FormatParameters^ parameters, CK_SLOT_ID slotId) 
{
	using namespace Aladdin; IntPtr ptrList = IntPtr::Zero; 

	// получить таблицу адресов дополнительных функций PKCS11		
	AE_CHECK_PKCS11(Aladdin::CAPI::SCard::APDU::Pro::ETC_GetFunctionListEx(ptrList)); 

    // выполнить преобразование типа
	ETCK_FUNCTION_LIST_EX_PTR pFunctionListEx = (ETCK_FUNCTION_LIST_EX_PTR)ptrList.ToPointer(); 
		
    // проверить необходимость поддержки FIPS и 2048-битных ключей RSA
	CK_BBOOL loadFIPS  = parameters->FIPS   ->Value ? CK_TRUE : CK_FALSE;
	CK_BBOOL loadRSA2k = parameters->RSA2048->Value ? CK_TRUE : CK_FALSE;

    // проверить возможность поддержки FIPS
	if (loadFIPS) { CK_BBOOL fips = IsFeatureSupported(module, slotId, ETCKA_FIPS_SUPPORTED);

        // при невозможности поддержки выбросить исключение
		if (!fips) throw gcnew Exception("FIPS support requested, but not supported");
    }
    // проверить возможность поддержки 2048-битных ключей RSA
	if (loadRSA2k) { CK_BBOOL rsa2k = IsFeatureSupported(module, slotId, ETCKA_RSA_2048_SUPPORTED);

        // при невозможности поддержки выбросить исключение
		if (!rsa2k) throw gcnew Exception("RSA2048 support requested, but not supported");
    }
    // прочитать минимальный размер пин-кода
	CK_ULONG pinLen = parameters->User->MinLengthPIN->Value;

    // извлечь метку
	array<BYTE>^ label = Encoding::UTF8->GetBytes(parameters->Label->Value);

	// скопировать метку
	CK_UTF8CHAR ptrLabel[32] = {0}; Marshal::Copy(label, 0, IntPtr(ptrLabel), label->Length); 

    // дополнить метку пробелами
    if (label->Length < 32) std::memset(ptrLabel + label->Length, 0x20, 32 - label->Length);  

    // извлечь значения пин-кодов
	array<BYTE>^ soPIN   = Encoding::UTF8->GetBytes(adminPIN);
	array<BYTE>^ userPIN = Encoding::UTF8->GetBytes(parameters->User->DefaultPIN->Value);

    // проверить корректность размера пин-кода
    if ((CK_ULONG)userPIN->Length < pinLen) throw gcnew ArgumentOutOfRangeException(); 

    // определить адрес паролей
	pin_ptr<CK_BYTE> ptrSoPIN   = (soPIN  ->Length > 0) ? &soPIN  [0] : nullptr; 
	pin_ptr<CK_BYTE> ptrUserPIN = (userPIN->Length > 0) ? &userPIN[0] : nullptr; 

    // извлечь максимальное число попв=ыток ввода пин-кода
	CK_ULONG retryCounterAdmin = parameters->Admin->MaxAttempts->Value; 
	CK_ULONG retryCounterUser  = parameters->User ->MaxAttempts->Value; 

	// открыть сеанс форматирования
    CK_SESSION_HANDLE hSession;
	AE_CHECK_PKCS11(pFunctionListEx->ETC_InitTokenInit(
        slotId, ptrSoPIN, soPIN->Length, retryCounterAdmin, ptrLabel, &hSession
    ));
    try { 
        // при наличии параметра форматирования
        if (parameters->FormatKey->Value != nullptr && parameters->FormatKey->Value != "default")
        {
			// закодировать значение метки
			array<BYTE>^ encodedLabel = Encoding::UTF8->GetBytes(gcnew String("OLDKEY")); 

			// закодировать значение ключа
			array<BYTE>^ encodedKey = Encoding::UTF8->GetBytes(parameters->FormatKey->Value); 

			// создать виртуальный сеанс
			CK_SESSION_HANDLE hVirtualSession; 
			AE_CHECK_PKCS11(pFunctionListEx->ETC_CreateVirtualSession(&hVirtualSession));
			try {
				// вычислить хэш-значение ключа
				array<BYTE>^ digestKey = HashStartKey(module, hVirtualSession, encodedKey); 

				// создать объект ключа
				module->CreateObject(hSession, gcnew array<PKCS11::Attribute^> { 
					gcnew PKCS11::Attribute(CKA_CLASS   , (CK_ULONG)CKO_SECRET_KEY  ), 
					gcnew PKCS11::Attribute(CKA_KEY_TYPE, (CK_ULONG)CKK_DES2		),
					gcnew PKCS11::Attribute(CKA_LABEL   , label						),
					gcnew PKCS11::Attribute(CKA_VALUE   , digestKey					)
				});
			}
			// закрыть открытый сеанс
			finally { module->CloseSession(hVirtualSession); }
        }
        // при наличии параметра форматирования
        if (parameters->NextFormatKey->Value != nullptr && parameters->NextFormatKey->Value != "default")
        {
 			// закодировать значение метки
			array<BYTE>^ encodedLabel = Encoding::UTF8->GetBytes(gcnew String("NEWKEY")); 

			// закодировать значение ключа
			array<BYTE>^ encodedKey = Encoding::UTF8->GetBytes(parameters->NextFormatKey->Value); 

			// создать виртуальный сеанс
			CK_SESSION_HANDLE hVirtualSession; 
			AE_CHECK_PKCS11(pFunctionListEx->ETC_CreateVirtualSession(&hVirtualSession));
			try {
				// вычислить хэш-значение ключа
				array<BYTE>^ digestKey = HashStartKey(module, hVirtualSession, encodedKey); 

				// создать объект ключа
				module->CreateObject(hSession, gcnew array<PKCS11::Attribute^> { 
					gcnew PKCS11::Attribute(CKA_CLASS   , (CK_ULONG)CKO_SECRET_KEY  ), 
					gcnew PKCS11::Attribute(CKA_KEY_TYPE, (CK_ULONG)CKK_DES2		),
					gcnew PKCS11::Attribute(CKA_LABEL   , label						),
					gcnew PKCS11::Attribute(CKA_VALUE   , digestKey					)
				});
			}
			// закрыть открытый сеанс
			finally { module->CloseSession(hVirtualSession); }
        }
        // создать объект на смарт-карте
        module->CreateObject(hSession, gcnew array<PKCS11::Attribute^> { 
			module->CreateAttribute(CKA_CLASS			, (UInt64  )CKO_HW_FEATURE		), 
			module->CreateAttribute(CKA_HW_FEATURE_TYPE	, (UInt64  )ETCKH_TOKEN_OBJECT	),
			module->CreateAttribute(ETCKA_RSA_2048      , (CK_BBOOL)loadRSA2k			),
			module->CreateAttribute(ETCKA_FIPS          , (CK_BBOOL)loadFIPS			)
		});
        // прочитать параметры форматирования
		CK_ULONG historySize = parameters->PIN->History   ->Value;
		CK_ULONG minPinAge   = parameters->PIN->MinAge    ->Value;
		CK_ULONG maxPinAge   = parameters->PIN->MaxAge    ->Value;
		CK_ULONG warnPeriod  = parameters->PIN->WarningAge->Value;

        // прочитать параметры форматирования
        CK_ULONG numbers  = (CK_ULONG)parameters->PIN->Complexity->Digits       ->Value;  
        CK_ULONG upper    = (CK_ULONG)parameters->PIN->Complexity->Uppers       ->Value;  
        CK_ULONG lower    = (CK_ULONG)parameters->PIN->Complexity->Lowers       ->Value;  
        CK_ULONG special  = (CK_ULONG)parameters->PIN->Complexity->Specials     ->Value; 
		CK_ULONG repeated =           parameters->PIN->Complexity->RepeatedChars->Value;  

        // создать объект с указанными атрибутами
		module->CreateObject(hSession, gcnew array<PKCS11::Attribute^> { 
			module->CreateAttribute(CKA_CLASS             , (UInt64  )CKO_HW_FEATURE			),
			module->CreateAttribute(CKA_HW_FEATURE_TYPE   , (UInt64  )ETCKH_PIN_POLICY			),
			module->CreateAttribute(ETCKA_PIN_POLICY_TYPE , (UInt64  )ETCKPT_GENERAL_PIN_POLICY	),
			module->CreateAttribute(ETCKA_PIN_MIX_CHARS   , (CK_BBOOL)CK_FALSE					),
			module->CreateAttribute(ETCKA_PIN_MIN_AGE     , (UInt64  )minPinAge					),
			module->CreateAttribute(ETCKA_PIN_MAX_AGE     , (UInt64  )maxPinAge					),
			module->CreateAttribute(ETCKA_PIN_WARN_PERIOD , (UInt64  )warnPeriod				),
			module->CreateAttribute(ETCKA_PIN_MIN_LEN     , (UInt64  )pinLen					),
			module->CreateAttribute(ETCKA_PIN_HISTORY_SIZE, (UInt64  )historySize				),
			module->CreateAttribute(ETCKA_PIN_MAX_REPEATED, (UInt64  )repeated					),
			module->CreateAttribute(ETCKA_PIN_NUMBERS     , (UInt64  )numbers					),
			module->CreateAttribute(ETCKA_PIN_UPPER_CASE  , (UInt64  )upper						),
			module->CreateAttribute(ETCKA_PIN_LOWER_CASE  , (UInt64  )lower						),
			module->CreateAttribute(ETCKA_PIN_SPECIAL     , (UInt64  )special					)
		});
        // указать атрибуты объектов
        CK_BBOOL modifiablePC = CK_FALSE; CK_ULONG fPrivateCaching = ETCKH_PRIVATE_CACHING;         
                
        // прочитать параметр форматирования
        CK_ULONG etckCacheMode = (CK_ULONG)parameters->CacheMode->Value;

        // создать объект с указанными атрибутами
		module->CreateObject(hSession, gcnew array<PKCS11::Attribute^> { 
			module->CreateAttribute(CKA_CLASS             , (UInt64  )CKO_HW_FEATURE		),
			module->CreateAttribute(CKA_HW_FEATURE_TYPE   , (UInt64  )ETCKH_PRIVATE_CACHING	),
			module->CreateAttribute(CKA_MODIFIABLE		  , (CK_BBOOL)CK_FALSE				),
			module->CreateAttribute(ETCKA_CACHE_PRIVATE   , (UInt64  )etckCacheMode			)
		});
        // прочитать параметр форматирования
		CK_BBOOL toBeChanged = parameters->User->MustFirstChange->Value ? CK_TRUE : CK_FALSE;

		// инициализировать пин-код пользователя
		AE_CHECK_PKCS11(pFunctionListEx->ETC_InitPIN(
            hSession, ptrUserPIN, userPIN->Length, retryCounterUser, toBeChanged
        ));
        // завершить форматирование
        AE_CHECK_PKCS11(pFunctionListEx->ETC_InitTokenFinal(hSession));
    }
    // закрыть открытый сеанс
    finally { module->CloseSession(hSession); } 
}

///////////////////////////////////////////////////////////////////////////
// Апплет eToken Pro
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::Pro::Applet::Format(
	String^ adminPIN, SCard::FormatParameters^ parameters) 
{$
	// преобразовать тип параметров
	FormatParameters^ params = dynamic_cast<FormatParameters^>(parameters);

	// проверить корректность типа параметров
	if (params == nullptr) throw gcnew ArgumentException();  

    // загрузить модуль PKCS11
	PKCS11::Module^ module = PKCS11::Module::Create(gcnew NativeAPI()); 

    // перечислить считыватели со вставленной смарт-картой
    array<UInt64>^ slotsIds = module->GetSlotList(true);

    // для всех считывателей
	for (int i = 0; i < slotsIds->Length; i++)
	{
        // получить информацию считывателя
	    PKCS11::SlotInfo^ info = module->GetSlotInfo(slotsIds[i]);

        // проверить совпадение имени
		if (info->SlotDescription != Card->Reader->Name) continue; 

        // закрыть все сеансы смарт-карты
		module->CloseAllSessions(slotsIds[i]); 

        // выполнить форматирование смарт-карты
        PerformFormat(module, adminPIN, params, (CK_SLOT_ID)slotsIds[i]); return;  
    }
	// при ошибке выбросить исключение
	throw gcnew NotFoundException(); 
}
