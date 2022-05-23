#include "..\stdafx.h"
#include "X942NKeyPairGenerator.h"
#include "X942Encoding.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X942NKeyPairGenerator.tmh"
#endif 

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace X942 
{
///////////////////////////////////////////////////////////////////////////
// Установка параметров ключа
///////////////////////////////////////////////////////////////////////////
private ref class ParamAction
{
	// параметры ключа
	private: IntPtr ptrBlob; private: DWORD cbBlob; 

	// конструктор
	public: ParamAction(IntPtr ptrBlob, DWORD cbBlob)
	{
		// сохранить переданные параметры
		this->ptrBlob = ptrBlob; this->cbBlob = cbBlob; 
	}
	// установить параметры ключа
	public: void Invoke(CAPI::CNG::Handle^ hKey)
	{
		// установить параметры 
		hKey->SetParam(NCRYPT_DH_PARAMETERS_PROPERTY, IntPtr(ptrBlob), cbBlob, 0); 
	}
}; 
}}}}}

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::CNG::Microsoft::X942::NKeyPairGenerator::Generate(
	CAPI::CNG::Container^ container, String^ keyOID, DWORD keyType, BOOL exportable) 
{$
	// извлечь параметры 
	ANSI::X942::IParameters^ parameters = (ANSI::X942::IParameters^)Parameters; 

	// определить требуемый размер буфера
	DWORD cbBlob = Encoding::GetParametersBlob(parameters, 0, 0); std::vector<BYTE> vecBlob(cbBlob); 

	// выделить буфер требуемого размера
	BCRYPT_DH_PARAMETER_HEADER* pbBlob = (BCRYPT_DH_PARAMETER_HEADER*)&vecBlob[0]; 

	// получить структуру для импорта параметров
	cbBlob = Encoding::GetParametersBlob(parameters, pbBlob, cbBlob); 

	// создать функцию установки парамтеров
	ParamAction^ paramAction = gcnew ParamAction(IntPtr(pbBlob), cbBlob); 

	// указать функцию установки парамтеров
	Action<CAPI::CNG::Handle^>^ action = gcnew Action<CAPI::CNG::Handle^>(
		paramAction, &ParamAction::Invoke
	); 
	// сгенерировать пару ключей
	return Generate(container, NCRYPT_DH_ALGORITHM, keyType, exportable, action, 0); 
}

