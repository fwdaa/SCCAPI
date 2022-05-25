#include "StdAfx.h"
#include "LaserApplet.h"
#include "NativeAPI.h"

#define CK_Win32
#include "cryptoki/asepkcs.h"
#include "cryptoki/C_Control.h"
#include "TracePKCS11.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "LaserFormat.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� �������������� � �������
///////////////////////////////////////////////////////////////////////////////
static void AuthenticateWipe(Aladdin::PKCS11::Module^ module, 
    CK_SLOT_ID slotId, String^ adminPIN, 
	Aladdin::CAPI::SCard::Applet^ applet)
{
    // �������� ����� ���������� �������
	CK_BYTE buffer[3] = {0}; CK_ULONG ulSize = sizeof(buffer); 

	// �������� ������ �������������� 
    AE_CHECK_PKCS11(Aladdin::CAPI::SCard::APDU::Laser::C_Control(
		slotId, CONTROL_GET_SO_PIN_INFO, IntPtr(buffer), IntPtr(&ulSize)
	));
    // ��������� ������������ ��������������
    if (buffer[0] == 0) return; if (buffer[0] != 1 && buffer[0] != 2)
    {
        // ��� ������ ��������� ����������
        throw gcnew InvalidOperationException(); 
    }
    // ��������� ����������� ��������������
    if (buffer[1] == 0) throw gcnew Aladdin::CAPI::AuthenticationException(); 

	// ������� ����� �� �����-������
	UInt64 hSession = module->OpenSession(slotId, CKF_RW_SESSION);

	// �������� ������� ��������������
	try { module->Logout(hSession); } finally { module->CloseSession(hSession); }

    // ��������� �������������� �������������� ������������
	module->Login(hSession, CKU_SO, adminPIN); ulSize = 0;
	try { 
		// ��������� �������
		AE_CHECK_PKCS11(Aladdin::CAPI::SCard::APDU::Laser::C_Control(
			slotId, CONTROL_WIPE_CARD_CONTENTS, IntPtr::Zero, IntPtr(&ulSize)
		)); 
	}
    // �������� ����������� ��������������
	finally { module->Logout(hSession); }  
}

///////////////////////////////////////////////////////////////////////////////
// ���������� ��������� ��������������
///////////////////////////////////////////////////////////////////////////////
static void SetComplexity(CK_SLOT_ID slotId, 
	Aladdin::CAPI::SCard::APDU::Laser::FormatParameters^ parameters) 
{
    using namespace Aladdin::CAPI::SCard::APDU::Laser; 

    // �������� ������ ��� ��������� ����������
	PINsComplexityStruct pinsComplexity = {0}; CK_ULONG ulSize = sizeof(pinsComplexity); 

	// �������� ��������� �����-�����
    AE_CHECK_PKCS11(Aladdin::CAPI::SCard::APDU::Laser::C_Control(
		slotId, CONTROL_GET_COMPLEXITY, IntPtr(&pinsComplexity), IntPtr(&ulSize)
	));
    // ������� ��� �������������� ������������
	pinsComplexity.userIsBiometric = (BYTE)parameters->User->LoginType->Value;

	// ���������� ���������� ���������
	pinsComplexity.adminIsChalRes				= parameters->Admin->UseResponse          ->Value;
	pinsComplexity.adminPinHistoryCount			= parameters->Admin->PIN->History         ->Value;
	pinsComplexity.maxAttemptsUserA				= parameters->Admin->PIN->MaxAttempts     ->Value;
	pinsComplexity.userPinHistoryCount			= parameters->User ->PIN->History         ->Value;
	pinsComplexity.maxAttemptsUser				= parameters->User ->PIN->MaxAttempts     ->Value;
	pinsComplexity.maxUnblockUser				= parameters->User ->PIN->MaxUnlocks      ->Value;
	pinsComplexity.userMustChange				= parameters->User ->PIN->MustFirstChange ->Value;
	pinsComplexity.userMustChangeAfterUnlock	= parameters->User ->PIN->MustUnlockChange->Value;
	pinsComplexity.deltaInDays					= parameters->ExpiredTimePIN              ->Value;
	pinsComplexity.deltaInMinutes				= parameters->CacheTimePIN                ->Value;

	// ���������� ���������� ��������� ���������
	pinsComplexity.maxCharsA			= parameters->Admin->PIN->Complexity-> MaxChars				->Value; 
	pinsComplexity.minCharsA			= parameters->Admin->PIN->Complexity-> MinChars				->Value;
	pinsComplexity.minAlphaNumericA		= parameters->Admin->PIN->Complexity-> MinAlphaNumerics		->Value;
	pinsComplexity.minNonAlphaNumericA	= parameters->Admin->PIN->Complexity-> MinNonAlphaNumerics	->Value;
	pinsComplexity.minAlphaBeticA		= parameters->Admin->PIN->Complexity-> MinAlphabetics		->Value;
	pinsComplexity.minLowerA			= parameters->Admin->PIN->Complexity-> MinLowers			->Value;
	pinsComplexity.minUpperA			= parameters->Admin->PIN->Complexity-> MinUppers			->Value;
	pinsComplexity.minNumA				= parameters->Admin->PIN->Complexity-> MinDigits 			->Value;
	pinsComplexity.occurrenceA			= parameters->Admin->PIN->Complexity-> RepeatedChars 		->Value;
	pinsComplexity.sequenceA			= parameters->Admin->PIN->Complexity-> SequenceChars		->Value;
	pinsComplexity.maxChars				= parameters->User ->PIN->Complexity -> MaxChars			->Value;
	pinsComplexity.minChars				= parameters->User ->PIN->Complexity -> MinChars			->Value;
	pinsComplexity.minAlphaNumeric		= parameters->User ->PIN->Complexity -> MinAlphaNumerics	->Value;
	pinsComplexity.minNonAlphaNumeric	= parameters->User ->PIN->Complexity -> MinNonAlphaNumerics	->Value;
	pinsComplexity.minAlphaBetic		= parameters->User ->PIN->Complexity -> MinAlphabetics		->Value;
	pinsComplexity.minLower				= parameters->User ->PIN->Complexity -> MinLowers			->Value;
	pinsComplexity.minUpper				= parameters->User ->PIN->Complexity -> MinUppers			->Value;
	pinsComplexity.minNum				= parameters->User ->PIN->Complexity -> MinDigits 			->Value;
	pinsComplexity.occurrence			= parameters->User ->PIN->Complexity -> RepeatedChars   	->Value;
	pinsComplexity.sequence				= parameters->User ->PIN->Complexity -> SequenceChars   	->Value;

    // ��������� �������� PIN-���� ���������
    if (parameters->ActivationPIN->Value == nullptr) pinsComplexity.activationPINLen = 0; 
    else {
        // ������������ PIN-��� ���������
        array<BYTE>^ encodedPIN = Encoding::UTF8->GetBytes(parameters->ActivationPIN->Value); 

        // ������� ������ PIN-����
        pinsComplexity.activationPINLen = encodedPIN->Length;

        // ����������� PIN-���
        Marshal::Copy(encodedPIN, 0, IntPtr(pinsComplexity.activationPIN), encodedPIN->Length); 
    }
    // ��������� �������� PIN-���� �����������
    if (parameters->DeactivationPIN->Value == nullptr) pinsComplexity.deactivationPINLen = 0; 
    else {
        // ������������ PIN-��� �����������
        array<BYTE>^ encodedPIN = Encoding::UTF8->GetBytes(parameters->DeactivationPIN->Value); 

        // ������� ������ PIN-����
        pinsComplexity.deactivationPINLen = encodedPIN->Length;

        // ����������� PIN-���
        Marshal::Copy(encodedPIN, 0, IntPtr(pinsComplexity.deactivationPIN), encodedPIN->Length); 
    }
    // ��������� ������� DS-����������
    if (parameters->DS == nullptr) pinsComplexity.dsSupport = 0;

    // ������� ������� ��������� DS-����������
    else { pinsComplexity.dsSupport = 1;
		
		// ������� ����� �����������
	    pinsComplexity.DSVerificationPolicy		= (BYTE)parameters->DS->CacheMode->Value;

        // ��������� DS-���������
	    pinsComplexity.DSSynchOption			= parameters->DS->UserSynchronize->Value;
	    pinsComplexity.max1024DSKeys			= parameters->DS->Max1024Keys	 ->Value;
	    pinsComplexity.max2048DSKeys			= parameters->DS->Max2048Keys	 ->Value;
	    pinsComplexity.maxAttemptsUserDSPIN		= parameters->DS->PIN->MaxAttempts ->Value;
	    pinsComplexity.maxUnblockUserDSPIN		= parameters->DS->PIN->MaxUnlocks  ->Value;
	    pinsComplexity.maxAttemptsUserDSPUK		= parameters->DS->PUK->MaxAttempts ->Value;
	    pinsComplexity.maxUnblockUserDSPUK		= parameters->DS->PUK->MaxUnlocks  ->Value;

        // ��������� DS-��������� ���������
	    pinsComplexity.maxCharsDSPIN			= parameters->DS->PIN->Complexity-> MaxChars			->Value; 
	    pinsComplexity.minCharsDSPIN			= parameters->DS->PIN->Complexity-> MinChars			->Value;
	    pinsComplexity.minAlphaNumericDSPIN		= parameters->DS->PIN->Complexity-> MinAlphaNumerics	->Value;
	    pinsComplexity.minNonAlphaNumericDSPIN	= parameters->DS->PIN->Complexity-> MinNonAlphaNumerics	->Value;
	    pinsComplexity.minAlphaBeticDSPIN		= parameters->DS->PIN->Complexity-> MinAlphabetics		->Value;
	    pinsComplexity.minLowerDSPIN			= parameters->DS->PIN->Complexity-> MinLowers			->Value;
	    pinsComplexity.minUpperDSPIN			= parameters->DS->PIN->Complexity-> MinUppers			->Value;
	    pinsComplexity.minNumDSPIN				= parameters->DS->PIN->Complexity-> MinDigits 			->Value;
	    pinsComplexity.occurrenceDSPIN			= parameters->DS->PIN->Complexity-> RepeatedChars		->Value;
	    pinsComplexity.sequenceDSPIN			= parameters->DS->PIN->Complexity-> SequenceChars   	->Value;
	    pinsComplexity.maxCharsDSPUK			= parameters->DS->PUK->Complexity-> MaxChars			->Value;
	    pinsComplexity.minCharsDSPUK			= parameters->DS->PUK->Complexity-> MinChars			->Value;
	    pinsComplexity.minAlphaNumericDSPUK		= parameters->DS->PUK->Complexity-> MinAlphaNumerics	->Value;
	    pinsComplexity.minNonAlphaNumericDSPUK	= parameters->DS->PUK->Complexity-> MinNonAlphaNumerics	->Value;
	    pinsComplexity.minAlphaBeticDSPUK		= parameters->DS->PUK->Complexity-> MinAlphabetics		->Value;
	    pinsComplexity.minLowerDSPUK			= parameters->DS->PUK->Complexity-> MinLowers			->Value;
	    pinsComplexity.minUpperDSPUK			= parameters->DS->PUK->Complexity-> MinUppers			->Value;
	    pinsComplexity.minNumDSPUK				= parameters->DS->PUK->Complexity-> MinDigits 			->Value;
	    pinsComplexity.occurrenceDSPUK			= parameters->DS->PUK->Complexity-> RepeatedChars		->Value;
	    pinsComplexity.sequenceDSPUK			= parameters->DS->PUK->Complexity-> SequenceChars   	->Value;
    }
    // ��� ������� ���������� �����������������
    if (pinsComplexity.userIsBiometric >= 3 && parameters->User->Bio != nullptr)
    {
        // ��������� ��������� �����������������
        pinsComplexity.maxBioFingers		= parameters->User->Bio->MaxFingers  ->Value;
        pinsComplexity.maxUnblockBio		= parameters->User->Bio->MaxUnlocks	 ->Value;
        pinsComplexity.imageQuality			= parameters->User->Bio->ImageQuality->Value;
        pinsComplexity.enrollmentPurpose	= parameters->User->Bio->EnrollFar	 ->Value;
    }
	// ���������� ��������� �����-�����
    AE_CHECK_PKCS11(Aladdin::CAPI::SCard::APDU::Laser::C_Control(
		slotId, CONTROL_SET_COMPLEXITY, IntPtr(&pinsComplexity), IntPtr(&ulSize)
	));
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������������
///////////////////////////////////////////////////////////////////////////////
static void PerformFormat(Aladdin::PKCS11::Module^ module, 
	CK_SLOT_ID slotId, String^ adminPIN, 
	Aladdin::CAPI::SCard::APDU::Laser::FormatParameters^ parameters) 
{
	// ���������� ��������� �����-�����
    SetComplexity(slotId, parameters);

	// ���������������� �����-�����
	module->InitToken(slotId, adminPIN, parameters->Label->Value);

    // ��� �������� PIN-���� ������������
    if (parameters->User->DefaultPIN->Value != nullptr)
    {
	    // ������� ����� 
	    UInt64 hSession = module->OpenSession(slotId, CKF_RW_SESSION);
        try { 
            // ��������� �������������� �������������� ������������
		    module->Login(hSession, CKU_SO, adminPIN); 

            // ���������� PIN-��� ������������
		    try { module->InitPIN(hSession, parameters->User->DefaultPIN->Value); }

            // �������� ����������� ��������������
		    finally { module->Logout(hSession); }  
        }
	    // ������� ����� ������������
	    finally { module->CloseSession(hSession); } 
    }
}

///////////////////////////////////////////////////////////////////////////
// ������ ��������������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::Laser::Applet::Format(
    String^ adminPIN, SCard::FormatParameters^ parameters) 
{$
	// ������������� ��� ����������
	FormatParameters^ params = dynamic_cast<FormatParameters^>(parameters); 

	// ��������� ������������ ���� ����������
	if (params == nullptr && parameters != nullptr) throw gcnew ArgumentException();  

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

        // ��������� �������������� � �������
        AuthenticateWipe(module, (CK_SLOT_ID)slotsIds[i], adminPIN, this); 

        // ��������� ������� ���������� ��������������
        if (parameters == nullptr) return; 
            
        // ��������� ��������������
        PerformFormat(module, (CK_SLOT_ID)slotsIds[i], adminPIN, params); return;  
    }
	// ��� ������ ��������� ����������
	throw gcnew NotFoundException(); 
}
