#pragma once

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU 
{
    ///////////////////////////////////////////////////////////////////////////
	// LibAPDU-����� ����������
    ///////////////////////////////////////////////////////////////////////////
	class CSCardException : public libapdu::IException 
	{
        // �����������
		public: CSCardException(libapdu::TErrorCode value) { this->value = value; } 
        // ����������
		public: virtual ~CSCardException() {} private: libapdu::TErrorCode value;

		// ���������� libapdu::IException
		public: virtual libapdu::TErrorCode code() override { return value; } 
	};
    ///////////////////////////////////////////////////////////////////////////
	// LibAPDU-����� �������� ������ �����-�����
    ///////////////////////////////////////////////////////////////////////////
	class CSCardSender : public libapdu::ISender
	{			
        // ����� ������ �� �����-������ � ATR �����-�����
	    private: gcroot<PCSC::ReaderSession^> session; libapdu::TBytes ATR;

        // �����������
		public: CSCardSender(PCSC::ReaderSession^ session, array<BYTE>^ atr) 
		{
            // ��������� ���������� ���������
			this->session = session; ATR.resize(atr->Length); 

			// ����������� �������� ATR
			Marshal::Copy(atr, 0, IntPtr(&ATR[0]), atr->Length); 
		}
		// �������� ATR �����-�����
		public: virtual libapdu::TBytes atr() override { return ATR; }  

		// ��������� IOCTL �� ����������/�����
		public: virtual void control(uint32_t code, 
			const libapdu::TBytes& cmnd, libapdu::TBytes& resp) override; 

		// ��������� ������� �����-�����
		public: virtual void send(
			const libapdu::TBytes& capdu, libapdu::TBytes& rapdu) override; 
	};
}}}}
