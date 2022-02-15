#pragma once 

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Pro
{
///////////////////////////////////////////////////////////////////////////
// Допустимость отдельных символов в пин-коде
///////////////////////////////////////////////////////////////////////////
public enum class CharPermissibility { DontCare = 0, Forbid = 1, Enforce = 2 }; 

///////////////////////////////////////////////////////////////////////////
// Способ кэшироавания данных провайдером
///////////////////////////////////////////////////////////////////////////
public enum class ProviderCacheMode { Off = 0, Login = 1, On = 2 }; 

///////////////////////////////////////////////////////////////////////////
// Параметры сложности пин-кода
///////////////////////////////////////////////////////////////////////////
public ref class PinComplexity : SCard::FormatParameters
{
	// конструктор
	public: PinComplexity(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// признак использования цифр
		Digits = gcnew FormatParameter<CharPermissibility>(
			1, CharPermissibility::DontCare, 
			gcnew FormatValidator::Range(0, 2)
		);   
	    // признак использования символов верхнего регистра
		Uppers = gcnew FormatParameter<CharPermissibility>(
			2, CharPermissibility::DontCare, 
			gcnew FormatValidator::Range(0, 2)
		);   
		// признак использования символов нижнего регистра
		Lowers = gcnew FormatParameter<CharPermissibility>(
			3, CharPermissibility::DontCare, 
			gcnew FormatValidator::Range(0, 2)
		);   
		// признак использования специальных символов
		Specials = gcnew FormatParameter<CharPermissibility>(
			4, CharPermissibility::DontCare, 
			gcnew FormatValidator::Range(0, 2)
		);   
		// максимальное число повторения символа в пин-коде
		RepeatedChars = gcnew FormatParameter<Int32>(
			5, 3, gcnew FormatValidator::Range(0, 16)
		); 
	}
	// параметры сложности пин-кода
    public: initonly FormatParameter<CharPermissibility>^ Digits;   
	public: initonly FormatParameter<CharPermissibility>^ Uppers;   
	public: initonly FormatParameter<CharPermissibility>^ Lowers;   
	public: initonly FormatParameter<CharPermissibility>^ Specials;   
    public: initonly FormatParameter<Int32>^              RepeatedChars; 
}; 
///////////////////////////////////////////////////////////////////////////
// Параметры использования пин-кода
///////////////////////////////////////////////////////////////////////////
public ref class PinParameters : SCard::FormatParameters
{
	// конструктор
	public: PinParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// параметры сложности
		Complexity = gcnew PinComplexity(1); 

		// размер кэша истории
		History = gcnew FormatParameter<Int32>(
			2, 10, gcnew FormatValidator::Range(0,  16)
		); 
		// минимальное время использования в днях
		MinAge = gcnew FormatParameter<Int32>(
			3, 0, gcnew FormatValidator::Range(0, 1000)
		); 
		// максимальное время использования в днях
		MaxAge = gcnew FormatParameter<Int32>(
			4, 1000, gcnew FormatValidator::Range(0, 1000)
		); 
		// время напоминания о необходимости смены в днях
		WarningAge = gcnew FormatParameter<Int32>(
			5, 0, gcnew FormatValidator::Range(0, 1000)
		); 
	}
	// параметры использования пин-кода
	public: initonly PinComplexity^          Complexity; 
	public: initonly FormatParameter<Int32>^ History; 
	public: initonly FormatParameter<Int32>^ MinAge; 
	public: initonly FormatParameter<Int32>^ MaxAge; 
	public: initonly FormatParameter<Int32>^ WarningAge; 
}; 

///////////////////////////////////////////////////////////////////////////
// Параметры администратора
///////////////////////////////////////////////////////////////////////////
public ref class AdminParameters : SCard::FormatParameters
{
	// конструктор
	public: AdminParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// максимальное число попыток ввода пин-кода
		MaxAttempts = gcnew FormatParameter<Int32>(
			1, 10, gcnew FormatValidator::Range(1, 15)
		); 
	}
	// параметры администратора
    public: initonly FormatParameter<Int32>^ MaxAttempts; 
};

///////////////////////////////////////////////////////////////////////////
// Параметры пользователя
///////////////////////////////////////////////////////////////////////////
public ref class UserParameters : SCard::FormatParameters
{
	// конструктор
	public: UserParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// пин-код 
		DefaultPIN = gcnew FormatParameter<String^>(
			1, "1234567890", gcnew FormatValidator::Length(4, 20)
		); 
		// максимальное число попыток ввода пин-кода
		MaxAttempts = gcnew FormatParameter<Int32>(
			2, 10, gcnew FormatValidator::Range(1, 15)
		); 
		// минимальный размер пин-кода 
		MinLengthPIN = gcnew FormatParameter<Int32>(
			3, 6, gcnew FormatValidator::Range(4, 20)
		); 
		// необходимость смены пин-кода при первом входе
		MustFirstChange = gcnew FormatParameter<Boolean>(4, false);  
	}
	// параметры пользователя
	public: initonly FormatParameter<String^>^ DefaultPIN; 
    public: initonly FormatParameter<Int32>^   MaxAttempts; 
    public: initonly FormatParameter<Int32>^   MinLengthPIN; 
	public: initonly FormatParameter<Boolean>^ MustFirstChange;  
};

///////////////////////////////////////////////////////////////////////////
// Параметры форматирования апплета
///////////////////////////////////////////////////////////////////////////
public ref class FormatParameters : SCard::FormatParameters
{
	// конструктор
	public: FormatParameters() : SCard::FormatParameters() 
	{
		// ключи форматирования
		FormatKey     = gcnew FormatParameter<String^>(1, nullptr); 
		NextFormatKey = gcnew FormatParameter<String^>(2, nullptr); 

		// метка смарт-карты
		Label = gcnew FormatParameter<String^>(
			3, "eToken", gcnew FormatValidator::Length(1, 32)
		); 
		// поддержка FIPS и 2048-битных ключей
		FIPS    = gcnew FormatParameter<Boolean>(4, false); 
		RSA2048 = gcnew FormatParameter<Boolean>(5, false); 

		// параметры администратора и пользователя
		Admin = gcnew AdminParameters(6); 
		User  = gcnew UserParameters (7); 

		// параметры использования пин-кода
		PIN = gcnew PinParameters(8); 

		// способ кэширования данных провайдером
		CacheMode = gcnew FormatParameter<Pro::ProviderCacheMode>(
			9, ProviderCacheMode::Login, gcnew FormatValidator::Range(0, 2)
		); 
	}
	// Параметры форматирования апплета
	public: initonly FormatParameter<String^>^					FormatKey; 
	public: initonly FormatParameter<String^>^					NextFormatKey; 
	public: initonly FormatParameter<String^>^					Label; 
    public: initonly FormatParameter<Boolean>^					FIPS; 
    public: initonly FormatParameter<Boolean>^					RSA2048; 
	public: initonly AdminParameters^							Admin; 
	public: initonly UserParameters^							User; 
	public: initonly PinParameters^								PIN; 
	public: initonly FormatParameter<Pro::ProviderCacheMode>^	CacheMode; 
}; 
}}}}}

