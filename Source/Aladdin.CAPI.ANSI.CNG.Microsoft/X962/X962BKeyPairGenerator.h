#pragma once
#include "X962Encoding.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace X962
{
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм генерации ключей
	///////////////////////////////////////////////////////////////////////////
	public ref class BKeyPairGenerator : CAPI::CNG::BKeyPairGenerator
	{
		// конструктор
		public: BKeyPairGenerator(CAPI::Factory^ factory, SecurityObject^ scope, 
			IRand^ rand, String^ provider, ANSI::X962::IParameters^ parameters) 
			
			// сохранить переданные параметры
			: CAPI::CNG::BKeyPairGenerator(factory, scope, rand, 
				provider, X962::Encoding::GetKeyName(parameters, AT_SIGNATURE), 0) 
		 
			// сохранить переданные параметры
			{ this->parameters = parameters; } private: ANSI::X962::IParameters^ parameters;
		 
		// сгенерировать пару ключей
		public: virtual KeyPair^ Generate(String^ keyOID) override; 
	};
}}}}}}
