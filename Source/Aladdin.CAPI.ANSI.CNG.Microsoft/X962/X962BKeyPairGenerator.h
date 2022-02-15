#pragma once
#include "X962Encoding.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace X962
{
	///////////////////////////////////////////////////////////////////////////
	// �������� ��������� ������
	///////////////////////////////////////////////////////////////////////////
	public ref class BKeyPairGenerator : CAPI::CNG::BKeyPairGenerator
	{
		// �����������
		public: BKeyPairGenerator(CAPI::Factory^ factory, SecurityObject^ scope, 
			IRand^ rand, String^ provider, ANSI::X962::IParameters^ parameters) 
			
			// ��������� ���������� ���������
			: CAPI::CNG::BKeyPairGenerator(factory, scope, rand, 
				provider, X962::Encoding::GetKeyName(parameters, AT_SIGNATURE), 0) 
		 
			// ��������� ���������� ���������
			{ this->parameters = parameters; } private: ANSI::X962::IParameters^ parameters;
		 
		// ������������� ���� ������
		public: virtual KeyPair^ Generate(String^ keyOID) override; 
	};
}}}}}}
