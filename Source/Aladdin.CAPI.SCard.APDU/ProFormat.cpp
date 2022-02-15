#include "StdAfx.h"
#include "ProApplet.h"
#include "NativeAPI.h"

#define CK_Win32
#include "cryptoki/cryptoki.h"
#include "cryptoki/eTPkcs11.h"
#include "TracePKCS11.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ProFormat.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���-�������� MD5 �� �����
///////////////////////////////////////////////////////////////////////////////
static array<BYTE>^ HashStartKey(Aladdin::PKCS11::Module^ module, 
    UInt64 hSession, array<BYTE>^ buffer)
{
	// �������� ����� ���������� �������
	array<BYTE>^ digest = gcnew array<BYTE>(16); 

    // ������� �������� �����������
	module->DigestInit(hSession, gcnew Aladdin::PKCS11::Mechanism(CKM_MD5));

	// ��������� �������� �����������
	module->DigestUpdate(hSession, buffer, 0, buffer->Length); 

    // ��������� �������� �����������
	CK_ULONG ulSize = module->DigestFinal(hSession, digest, (CK_ULONG)0); 

	// ������� ���-��������
	Array::Resize(digest, ulSize); return digest;  
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������� �������������� ������������
///////////////////////////////////////////////////////////////////////////////
static CK_BBOOL IsFeatureSupported(Aladdin::PKCS11::Module^ module, 
	CK_SLOT_ID nSlotID, CK_ULONG feature)
{
	using namespace Aladdin; 

    // ������� �������� ������� ��� ������
	array<PKCS11::Attribute^>^ tokenAttributes = gcnew array<PKCS11::Attribute^> { 
		module->CreateAttribute(CKA_CLASS          , (UInt64)CKO_HW_FEATURE    ), 
		module->CreateAttribute(CKA_HW_FEATURE_TYPE, (UInt64)ETCKH_TOKEN_OBJECT)
	};  
    // ������� ����������������� �����
	UInt64 hSession = module->OpenSession(nSlotID, CKF_RW_SESSION | CKF_SERIAL_SESSION);
    try { 
        // ����� ������� � ���������� ����������
		array<UInt64>^ objs = module->FindObjects(hSession, tokenAttributes);

		// ��������� ������� ������ ������ �������
		if (objs->Length == 0) return CK_FALSE; if (objs->Length > 1)
		{
			// ��� ������ ��������� ����������
			throw gcnew PKCS11::Exception(CKR_TEMPLATE_INCOMPLETE); 
		} 
		// ������� ��������� �������
		tokenAttributes = gcnew array<PKCS11::Attribute^> {
			module->CreateAttribute(feature, (CK_BBOOL)CK_FALSE)
		}; 
		// ����� ��������� �������
		tokenAttributes = module->GetAttributes(hSession, objs[0], tokenAttributes);

		// ������� ������� ���������
		return tokenAttributes[0]->Value[0] != 0;  
    }
    // ������� �������� �����
    finally { module->CloseSession(hSession); }
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������� ��������������
///////////////////////////////////////////////////////////////////////////////
static void PerformFormat(Aladdin::PKCS11::Module^ module, String^ adminPIN, 
    Aladdin::CAPI::SCard::APDU::Pro::FormatParameters^ parameters, CK_SLOT_ID slotId) 
{
	using namespace Aladdin; IntPtr ptrList = IntPtr::Zero; 

	// �������� ������� ������� �������������� ������� PKCS11		
	AE_CHECK_PKCS11(Aladdin::CAPI::SCard::APDU::Pro::ETC_GetFunctionListEx(ptrList)); 

    // ��������� �������������� ����
	ETCK_FUNCTION_LIST_EX_PTR pFunctionListEx = (ETCK_FUNCTION_LIST_EX_PTR)ptrList.ToPointer(); 
		
    // ��������� ������������� ��������� FIPS � 2048-������ ������ RSA
	CK_BBOOL loadFIPS  = parameters->FIPS   ->Value ? CK_TRUE : CK_FALSE;
	CK_BBOOL loadRSA2k = parameters->RSA2048->Value ? CK_TRUE : CK_FALSE;

    // ��������� ����������� ��������� FIPS
	if (loadFIPS) { CK_BBOOL fips = IsFeatureSupported(module, slotId, ETCKA_FIPS_SUPPORTED);

        // ��� ������������� ��������� ��������� ����������
		if (!fips) throw gcnew Exception("FIPS support requested, but not supported");
    }
    // ��������� ����������� ��������� 2048-������ ������ RSA
	if (loadRSA2k) { CK_BBOOL rsa2k = IsFeatureSupported(module, slotId, ETCKA_RSA_2048_SUPPORTED);

        // ��� ������������� ��������� ��������� ����������
		if (!rsa2k) throw gcnew Exception("RSA2048 support requested, but not supported");
    }
    // ��������� ����������� ������ ���-����
	CK_ULONG pinLen = parameters->User->MinLengthPIN->Value;

    // ������� �����
	array<BYTE>^ label = Encoding::UTF8->GetBytes(parameters->Label->Value);

	// ����������� �����
	CK_UTF8CHAR ptrLabel[32] = {0}; Marshal::Copy(label, 0, IntPtr(ptrLabel), label->Length); 

    // ��������� ����� ���������
    if (label->Length < 32) std::memset(ptrLabel + label->Length, 0x20, 32 - label->Length);  

    // ������� �������� ���-�����
	array<BYTE>^ soPIN   = Encoding::UTF8->GetBytes(adminPIN);
	array<BYTE>^ userPIN = Encoding::UTF8->GetBytes(parameters->User->DefaultPIN->Value);

    // ��������� ������������ ������� ���-����
    if ((CK_ULONG)userPIN->Length < pinLen) throw gcnew ArgumentOutOfRangeException(); 

    // ���������� ����� �������
	pin_ptr<CK_BYTE> ptrSoPIN   = (soPIN  ->Length > 0) ? &soPIN  [0] : nullptr; 
	pin_ptr<CK_BYTE> ptrUserPIN = (userPIN->Length > 0) ? &userPIN[0] : nullptr; 

    // ������� ������������ ����� ����=���� ����� ���-����
	CK_ULONG retryCounterAdmin = parameters->Admin->MaxAttempts->Value; 
	CK_ULONG retryCounterUser  = parameters->User ->MaxAttempts->Value; 

	// ������� ����� ��������������
    CK_SESSION_HANDLE hSession;
	AE_CHECK_PKCS11(pFunctionListEx->ETC_InitTokenInit(
        slotId, ptrSoPIN, soPIN->Length, retryCounterAdmin, ptrLabel, &hSession
    ));
    try { 
        // ��� ������� ��������� ��������������
        if (parameters->FormatKey->Value != nullptr && parameters->FormatKey->Value != "default")
        {
			// ������������ �������� �����
			array<BYTE>^ encodedLabel = Encoding::UTF8->GetBytes(gcnew String("OLDKEY")); 

			// ������������ �������� �����
			array<BYTE>^ encodedKey = Encoding::UTF8->GetBytes(parameters->FormatKey->Value); 

			// ������� ����������� �����
			CK_SESSION_HANDLE hVirtualSession; 
			AE_CHECK_PKCS11(pFunctionListEx->ETC_CreateVirtualSession(&hVirtualSession));
			try {
				// ��������� ���-�������� �����
				array<BYTE>^ digestKey = HashStartKey(module, hVirtualSession, encodedKey); 

				// ������� ������ �����
				module->CreateObject(hSession, gcnew array<PKCS11::Attribute^> { 
					gcnew PKCS11::Attribute(CKA_CLASS   , (CK_ULONG)CKO_SECRET_KEY  ), 
					gcnew PKCS11::Attribute(CKA_KEY_TYPE, (CK_ULONG)CKK_DES2		),
					gcnew PKCS11::Attribute(CKA_LABEL   , label						),
					gcnew PKCS11::Attribute(CKA_VALUE   , digestKey					)
				});
			}
			// ������� �������� �����
			finally { module->CloseSession(hVirtualSession); }
        }
        // ��� ������� ��������� ��������������
        if (parameters->NextFormatKey->Value != nullptr && parameters->NextFormatKey->Value != "default")
        {
 			// ������������ �������� �����
			array<BYTE>^ encodedLabel = Encoding::UTF8->GetBytes(gcnew String("NEWKEY")); 

			// ������������ �������� �����
			array<BYTE>^ encodedKey = Encoding::UTF8->GetBytes(parameters->NextFormatKey->Value); 

			// ������� ����������� �����
			CK_SESSION_HANDLE hVirtualSession; 
			AE_CHECK_PKCS11(pFunctionListEx->ETC_CreateVirtualSession(&hVirtualSession));
			try {
				// ��������� ���-�������� �����
				array<BYTE>^ digestKey = HashStartKey(module, hVirtualSession, encodedKey); 

				// ������� ������ �����
				module->CreateObject(hSession, gcnew array<PKCS11::Attribute^> { 
					gcnew PKCS11::Attribute(CKA_CLASS   , (CK_ULONG)CKO_SECRET_KEY  ), 
					gcnew PKCS11::Attribute(CKA_KEY_TYPE, (CK_ULONG)CKK_DES2		),
					gcnew PKCS11::Attribute(CKA_LABEL   , label						),
					gcnew PKCS11::Attribute(CKA_VALUE   , digestKey					)
				});
			}
			// ������� �������� �����
			finally { module->CloseSession(hVirtualSession); }
        }
        // ������� ������ �� �����-�����
        module->CreateObject(hSession, gcnew array<PKCS11::Attribute^> { 
			module->CreateAttribute(CKA_CLASS			, (UInt64  )CKO_HW_FEATURE		), 
			module->CreateAttribute(CKA_HW_FEATURE_TYPE	, (UInt64  )ETCKH_TOKEN_OBJECT	),
			module->CreateAttribute(ETCKA_RSA_2048      , (CK_BBOOL)loadRSA2k			),
			module->CreateAttribute(ETCKA_FIPS          , (CK_BBOOL)loadFIPS			)
		});
        // ��������� ��������� ��������������
		CK_ULONG historySize = parameters->PIN->History   ->Value;
		CK_ULONG minPinAge   = parameters->PIN->MinAge    ->Value;
		CK_ULONG maxPinAge   = parameters->PIN->MaxAge    ->Value;
		CK_ULONG warnPeriod  = parameters->PIN->WarningAge->Value;

        // ��������� ��������� ��������������
        CK_ULONG numbers  = (CK_ULONG)parameters->PIN->Complexity->Digits       ->Value;  
        CK_ULONG upper    = (CK_ULONG)parameters->PIN->Complexity->Uppers       ->Value;  
        CK_ULONG lower    = (CK_ULONG)parameters->PIN->Complexity->Lowers       ->Value;  
        CK_ULONG special  = (CK_ULONG)parameters->PIN->Complexity->Specials     ->Value; 
		CK_ULONG repeated =           parameters->PIN->Complexity->RepeatedChars->Value;  

        // ������� ������ � ���������� ����������
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
        // ������� �������� ��������
        CK_BBOOL modifiablePC = CK_FALSE; CK_ULONG fPrivateCaching = ETCKH_PRIVATE_CACHING;         
                
        // ��������� �������� ��������������
        CK_ULONG etckCacheMode = (CK_ULONG)parameters->CacheMode->Value;

        // ������� ������ � ���������� ����������
		module->CreateObject(hSession, gcnew array<PKCS11::Attribute^> { 
			module->CreateAttribute(CKA_CLASS             , (UInt64  )CKO_HW_FEATURE		),
			module->CreateAttribute(CKA_HW_FEATURE_TYPE   , (UInt64  )ETCKH_PRIVATE_CACHING	),
			module->CreateAttribute(CKA_MODIFIABLE		  , (CK_BBOOL)CK_FALSE				),
			module->CreateAttribute(ETCKA_CACHE_PRIVATE   , (UInt64  )etckCacheMode			)
		});
        // ��������� �������� ��������������
		CK_BBOOL toBeChanged = parameters->User->MustFirstChange->Value ? CK_TRUE : CK_FALSE;

		// ���������������� ���-��� ������������
		AE_CHECK_PKCS11(pFunctionListEx->ETC_InitPIN(
            hSession, ptrUserPIN, userPIN->Length, retryCounterUser, toBeChanged
        ));
        // ��������� ��������������
        AE_CHECK_PKCS11(pFunctionListEx->ETC_InitTokenFinal(hSession));
    }
    // ������� �������� �����
    finally { module->CloseSession(hSession); } 
}

///////////////////////////////////////////////////////////////////////////
// ������ eToken Pro
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::Pro::Applet::Format(
	String^ adminPIN, SCard::FormatParameters^ parameters) 
{$
	// ������������� ��� ����������
	FormatParameters^ params = dynamic_cast<FormatParameters^>(parameters);

	// ��������� ������������ ���� ����������
	if (params == nullptr) throw gcnew ArgumentException();  

    // ��������� ������ PKCS11
	PKCS11::Module^ module = PKCS11::Module::Create(gcnew NativeAPI()); 

    // ����������� ����������� �� ����������� �����-������
    array<UInt64>^ slotsIds = module->GetSlotList(true);

    // ��� ���� ������������
	for (int i = 0; i < slotsIds->Length; i++)
	{
        // �������� ���������� �����������
	    PKCS11::SlotInfo^ info = module->GetSlotInfo(slotsIds[i]);

        // ��������� ���������� �����
		if (info->SlotDescription != Card->Reader->Name) continue; 

        // ������� ��� ������ �����-�����
		module->CloseAllSessions(slotsIds[i]); 

        // ��������� �������������� �����-�����
        PerformFormat(module, adminPIN, params, (CK_SLOT_ID)slotsIds[i]); return;  
    }
	// ��� ������ ��������� ����������
	throw gcnew NotFoundException(); 
}
