#pragma once
#include "..\PKCS1\RSAPKCS1BSignHash.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PSS
{
    ///////////////////////////////////////////////////////////////////////
    // ������� ���-�������� RSA PSS
    ///////////////////////////////////////////////////////////////////////
	public ref class BSignHash : RSA::PKCS1::BSignHash
	{
		// ������������� ��������� ����������� � ������ salt-��������
		private: String^ hashOID; private: int saltLength; 

		// �����������
		public: BSignHash(String^ provider, 
			String^ hashOID, int saltLength) : RSA::PKCS1::BSignHash(provider) 
		{ 
			// ��������� ���������� ���������
			this->hashOID = hashOID; this->saltLength = saltLength;
		} 
		// ��������� ���-��������
		protected: virtual array<BYTE>^ Sign(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPrivateKey,  
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override; 
	};
}}}}}}}}
