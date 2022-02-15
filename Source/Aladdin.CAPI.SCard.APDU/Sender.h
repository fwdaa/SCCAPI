#pragma once

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU 
{
    ///////////////////////////////////////////////////////////////////////////
	// LibAPDU-класс исключения
    ///////////////////////////////////////////////////////////////////////////
	class CSCardException : public libapdu::IException 
	{
        // конструктор
		public: CSCardException(libapdu::TErrorCode value) { this->value = value; } 
        // деструктор
		public: virtual ~CSCardException() {} private: libapdu::TErrorCode value;

		// реализация libapdu::IException
		public: virtual libapdu::TErrorCode code() override { return value; } 
	};
    ///////////////////////////////////////////////////////////////////////////
	// LibAPDU-класс передачи команд смарт-карте
    ///////////////////////////////////////////////////////////////////////////
	class CSCardSender : public libapdu::ISender
	{			
        // сеанс работы со смарт-картой и ATR смарт-карты
	    private: gcroot<PCSC::ReaderSession^> session; libapdu::TBytes ATR;

        // конструктор
		public: CSCardSender(PCSC::ReaderSession^ session, array<BYTE>^ atr) 
		{
            // сохранить переданные параметры
			this->session = session; ATR.resize(atr->Length); 

			// скопировать значение ATR
			Marshal::Copy(atr, 0, IntPtr(&ATR[0]), atr->Length); 
		}
		// получить ATR смарт-карты
		public: virtual libapdu::TBytes atr() override { return ATR; }  

		// отправить IOCTL на смарткарту/ридер
		public: virtual void control(uint32_t code, 
			const libapdu::TBytes& cmnd, libapdu::TBytes& resp) override; 

		// отправить команду смарт-карте
		public: virtual void send(
			const libapdu::TBytes& capdu, libapdu::TBytes& rapdu) override; 
	};
}}}}
