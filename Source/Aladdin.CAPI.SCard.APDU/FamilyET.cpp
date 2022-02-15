#include "stdafx.h"
#include "Provider.h"

///////////////////////////////////////////////////////////////////////////////
// ƒополнительные определени€ трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "FamilyET.tmh"
#endif 

using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////
// —емейство eToken
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::SCard::APDU::ETFamily::Contains(array<BYTE>^ atr)
{$
	// список поддерживаемых ATR
	array<MaskATR^>^ atrs = gcnew array<MaskATR^> {

		// eTokenCard/M4.20
		gcnew MaskATR("3BF2180000C10A31FE50C80000", "FFFFFFFF00FFFFFFFFF0FFF000"), 

		// eTokenOS4 (T1 32k)
		gcnew MaskATR("3BF29800FFC11031FE55C80315", "FFFFFFFFFFFFFFFFFFFFFFFFFF"), 

		// eTokenOS4 (T1 16k) 
		gcnew MaskATR("3BE200FFC11031FE55C8029C", "FFFFFFFFFFFFFFFFFFFFFFFF"), 
	};
	// проверить принадлежность ATR
	return (atrs[0]->Contains(atr) || atrs[1]->Contains(atr) || atrs[2]->Contains(atr)); 
}

