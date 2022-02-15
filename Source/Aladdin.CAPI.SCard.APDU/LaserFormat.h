#pragma once 

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { namespace Laser
{
///////////////////////////////////////////////////////////////////////////////
// Параметры сложности пин-кода
///////////////////////////////////////////////////////////////////////////////
public ref class ComplexityParameters : SCard::FormatParameters
{
	// конструктор
	public: ComplexityParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// минимальное число символов
		MinChars = gcnew FormatParameter<Int32>(
			1, 4, gcnew FormatValidator::Range(4, 16)
		);   
		// максимальное число символов
		MaxChars =	gcnew FormatParameter<Int32>(
			2, 16, gcnew FormatValidator::Range(4, 16)
		);   
		// минимальное число букв и цифр
		MinAlphaNumerics = gcnew FormatParameter<Int32>(
			3, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// минимальное число не букв и цифр
		MinNonAlphaNumerics = gcnew FormatParameter<Int32>(
			4, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// минимальное число цифр
		MinDigits = gcnew FormatParameter<Int32>(
			5, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// минимальное число букв
		MinAlphabetics = gcnew FormatParameter<Int32>(
			6, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// минимальное число букв в верхнем регистре
		MinUppers = gcnew FormatParameter<Int32>(
			7, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// минимальное число букв в верхнем регистре
		MinLowers =	gcnew FormatParameter<Int32>(
			8, 0, gcnew FormatValidator::Range(0, 16)
		);   
		// максимальное число повторений символов в пин-коде
		RepeatedChars = gcnew FormatParameter<Int32>(
			9, 16, gcnew FormatValidator::Range(0, 16)
		);   
		// максимальное число повторений символов в пин-коде
		SequenceChars =	gcnew FormatParameter<Int32>(
			10, 16, gcnew FormatValidator::Range(0, 16)
		);   
	}
	// параметры сложности пин-кода
	public: initonly FormatParameter<Int32>^ MinChars;   
	public: initonly FormatParameter<Int32>^ MaxChars;   
	public: initonly FormatParameter<Int32>^ MinAlphaNumerics;   
	public: initonly FormatParameter<Int32>^ MinNonAlphaNumerics;   
	public: initonly FormatParameter<Int32>^ MinDigits;   
	public: initonly FormatParameter<Int32>^ MinAlphabetics;   
	public: initonly FormatParameter<Int32>^ MinUppers;   
	public: initonly FormatParameter<Int32>^ MinLowers;   
	public: initonly FormatParameter<Int32>^ RepeatedChars;   
	public: initonly FormatParameter<Int32>^ SequenceChars;   
};	

///////////////////////////////////////////////////////////////////////////////
// Параметры использования пин-кода
///////////////////////////////////////////////////////////////////////////////
public ref class PinParameters : SCard::FormatParameters
{
	// конструктор
	public: PinParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// сложность пин-кода
		Complexity = gcnew ComplexityParameters(1);   

		// максимальное число ввода пин-кода
		MaxAttempts = gcnew FormatParameter<Int32>(
			2, 10, gcnew FormatValidator::Range(1, 15)
		);   
	}
	// параметры использования пин-кода
	public: initonly ComplexityParameters^   Complexity;   
	public: initonly FormatParameter<Int32>^ MaxAttempts;   
}; 

public ref class AdminPinParameters : PinParameters
{
	// конструктор
	public: AdminPinParameters(int ordinal) : PinParameters(ordinal) 
	{
		// глубина истории пин-кода
		History = gcnew FormatParameter<Int32>(
			3, 0, gcnew FormatValidator::Range(0, 255)
		);   
	}
	// параметры использования пин-кода
	public: initonly FormatParameter<Int32>^ History;   
}; 

public ref class UserPinParameters : PinParameters
{
	// конструктор
	public: UserPinParameters(int ordinal) : PinParameters(ordinal) 
	{
		// глубина истории пин-кода
		History = gcnew FormatParameter<Int32>(
			3, 0, gcnew FormatValidator::Range(0, 255)
		);   
		// максимальное число разблокировок
		MaxUnlocks = gcnew FormatParameter<Int32>(
			4, 0, gcnew FormatValidator::Range(0, 15)
		);   
		// необходимость смены пин-кода после первого входа
		MustFirstChange = gcnew FormatParameter<Boolean>(5, false); 

		// необходимость смены пин-кода после разблокировки
		MustUnlockChange = gcnew FormatParameter<Boolean>(6, false); 
	}
	// параметры использования пин-кода
	public: initonly FormatParameter<Int32>^   History;   
	public: initonly FormatParameter<Int32>^   MaxUnlocks;   
	public: initonly FormatParameter<Boolean>^ MustFirstChange; 
	public: initonly FormatParameter<Boolean>^ MustUnlockChange; 

}; 

public ref class DSPinParameters : PinParameters
{
	// конструктор
	public: DSPinParameters(int ordinal) : PinParameters(ordinal) 
	{
		// максимальное число разблокировок
		MaxUnlocks = gcnew FormatParameter<Int32>(3, 
			0, gcnew FormatValidator::Range(0, 15)
		);   
	}
	// параметры использования пин-кода
	public: initonly FormatParameter<Int32>^ MaxUnlocks;   
}; 

///////////////////////////////////////////////////////////////////////////////
// Параметры биометрической аутентификации
///////////////////////////////////////////////////////////////////////////////
public ref class BiometricParameters : SCard::FormatParameters
{
	// конструктор
	public: BiometricParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// максимальное число разблокировок
		MaxUnlocks = gcnew FormatParameter<Int32>(
			1, 0, gcnew FormatValidator::Range(0, 15)
		);   
		// максимальное число отпечатков для аутентификации
		MaxFingers = gcnew FormatParameter<Int32>(
			2, 1, gcnew FormatValidator::Range(1, 10)
		);   
		// допустимое качество изображения отпечатков
		ImageQuality = gcnew FormatParameter<Int32>(
			3, 51, gcnew FormatValidator::Range(0, 100)
		);   
		// FAR биометрической аутентификации (21474836 – 1:100, 
		// 2147483 – 1:1000, 214748 – 1:10000, 21474 – 1:100000, 
		// 2147 – 1:1000000)
		EnrollFar = gcnew FormatParameter<Int32>(
			4, 214748, gcnew FormatValidator::Range(2147, 21474836)
		);   
	}
	// параметры биометрической аутентификации
	public: initonly FormatParameter<Int32>^ MaxUnlocks;   
	public: initonly FormatParameter<Int32>^ MaxFingers;   
	public: initonly FormatParameter<Int32>^ ImageQuality;   
	public: initonly FormatParameter<Int32>^ EnrollFar;   
}; 

///////////////////////////////////////////////////////////////////////////////
// Параметры администратора
///////////////////////////////////////////////////////////////////////////////
public ref class AdminParameters : SCard::FormatParameters
{
	// конструктор
	public: AdminParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// использование протокола "запрос-ответ"
		UseResponse = gcnew FormatParameter<Boolean>(1, false);   

		// параметры использования пин-кода
		PIN = gcnew AdminPinParameters(2); 
	}
	// параметры администратора
	public: initonly FormatParameter<Boolean>^ UseResponse;   
	public: initonly AdminPinParameters^       PIN; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Тип аутентификации пользователя
///////////////////////////////////////////////////////////////////////////////
public enum class UserLoginType { 
	None		= 0,  // отсутствует
	Pin			= 1,  // PIN-аутентификация
	Response	= 2,  // PIN-аутентификация "запрос-ответ"
	Bio			= 3,  // биометрическая аутентификация
	PinOrBio	= 4,  // PIN- или биометрическая аутентификация
	PinAndBio	= 5   // PIN-  и  биометрическая аутентификация
}; 

///////////////////////////////////////////////////////////////////////////////
// Параметры пользователя
///////////////////////////////////////////////////////////////////////////////
public ref class UserParameters : SCard::FormatParameters
{
	// конструктор
	public: UserParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// тип аутентификации
		LoginType =	gcnew FormatParameter<UserLoginType>(
			1, UserLoginType::Pin, gcnew FormatValidator::Range(1, 5)
		);   
		// пин-код
		DefaultPIN = gcnew FormatParameter<String^>(
			2, "11111111", gcnew FormatValidator::Length(4, 16, false)
		);   
		// параметры использования пин-кода
		PIN = gcnew UserPinParameters  (3); 

		// параметры биометрической аутентификации
		Bio = gcnew BiometricParameters(4); 
	}
	// параметры пользователя
	public: initonly FormatParameter<UserLoginType>^ LoginType;   
	public: initonly FormatParameter<String^>^       DefaultPIN;   
	public: initonly UserPinParameters  ^			 PIN; 
	public: initonly BiometricParameters^			 Bio; 
}; 

///////////////////////////////////////////////////////////////////////////
// Способ кэшироавания данных провайдером
///////////////////////////////////////////////////////////////////////////
public enum class ProviderCacheMode { Off = 0, Prompt = 1, On = 2 }; 

///////////////////////////////////////////////////////////////////////////
// Параметры DS
///////////////////////////////////////////////////////////////////////////
public ref class DSParameters : SCard::FormatParameters
{
	// конструктор
	public: DSParameters(int ordinal) : SCard::FormatParameters(ordinal) 
	{
		// параметры пин-кода и пук-кода
		PIN = gcnew DSPinParameters(1);   
		PUK = gcnew DSPinParameters(2);   

		// максимальное число 1024-битных ключей
		Max1024Keys = gcnew FormatParameter<Int32>(
			3, 2, gcnew FormatValidator::Range(2, 4)
		);   
		// максимальное число 2048-битных ключей
		Max2048Keys = gcnew FormatParameter<Int32>(
			4, 2, gcnew FormatValidator::Range(2, 4)
		);   
		// синхронизация с пользовательским PIN
		UserSynchronize = gcnew FormatParameter<Boolean>(5, false); 

		// cпособ кэшироавания данных провайдером
		CacheMode = gcnew FormatParameter<ProviderCacheMode>(
			6, ProviderCacheMode::Off
		); 
	}
	// параметры DS
	public: initonly DSPinParameters^					 PIN;   
	public: initonly DSPinParameters^					 PUK;   
	public: initonly FormatParameter<Int32>^			 Max1024Keys;   
	public: initonly FormatParameter<Int32>^			 Max2048Keys;   
	public: initonly FormatParameter<Boolean>^			 UserSynchronize; 
	public: initonly FormatParameter<ProviderCacheMode>^ CacheMode; 
}; 

///////////////////////////////////////////////////////////////////////////
// Параметры форматирования апплета
///////////////////////////////////////////////////////////////////////////
public ref class FormatParameters : SCard::FormatParameters
{
	// конструктор
	public: FormatParameters() : SCard::FormatParameters() 
	{
		// метка смарт-карты
		Label =	gcnew FormatParameter<String^>(
			1, "JaCarta PKI", gcnew FormatValidator::Length(1, 32, true)
		);   
		// параметры администратора и пользователя
		Admin = gcnew AdminParameters(2); 
		User  = gcnew UserParameters (3); 

		// параметры DS
		DS = gcnew DSParameters(4); 

		// время действия пин-кода в днях
		ExpiredTimePIN = gcnew FormatParameter<Int32>(
			5, 0, gcnew FormatValidator::Range(0, 9999)
		);   
		// время кэширования PIN в минутах
		CacheTimePIN = gcnew FormatParameter<Int32>(
			6, 0, gcnew FormatValidator::Range(0, 9999)
		);   
		// пин-код активации
		ActivationPIN = gcnew FormatParameter<String^>(
			7, nullptr, gcnew FormatValidator::Length(4, 16, false)
		);   
		// пин-код деактивации
		DeactivationPIN = gcnew FormatParameter<String^>(
			8, nullptr, gcnew FormatValidator::Length(4, 16, false)
		);   
	}
	// параметры форматирования апплета
	public: initonly FormatParameter<String^>^	Label;   
	public: initonly AdminParameters^			Admin; 
	public: initonly UserParameters^			User; 
	public: initonly DSParameters^				DS; 
	public: initonly FormatParameter<Int32>^	ExpiredTimePIN;   
	public: initonly FormatParameter<Int32>^	CacheTimePIN;   
	public: initonly FormatParameter<String^>^	ActivationPIN;   
	public: initonly FormatParameter<String^>^	DeactivationPIN;   
}; 
}}}}}
