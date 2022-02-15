#pragma once 

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Cryptotoken
{
///////////////////////////////////////////////////////////////////////////
// Параметры форматирования апплета
///////////////////////////////////////////////////////////////////////////
public ref class FormatParameters : SCard::FormatParameters
{
	// конструктор
	public: FormatParameters() 
	{
		// метка смарт-карты
		Label = gcnew FormatParameter<String^>(
			1, "JaCarta ГОСТ", gcnew FormatValidator::Length(1, 32)
		); 
		// пин-код пользователя
		UserPIN = gcnew FormatParameter<String^>(
			2, "1234567890", gcnew FormatValidator::Length(6, 30, false)
		); 
	}
	// параметры форматирования апплета
	public: initonly FormatParameter<String^>^ Label; 
	public: initonly FormatParameter<String^>^ UserPIN; 
}; 
}}}}}
