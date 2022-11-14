#pragma once
#include "crypto.h"

namespace Crypto { namespace SSL { 

///////////////////////////////////////////////////////////////////////////////
// Тип сертификата и аутентификации клиента
///////////////////////////////////////////////////////////////////////////////
#define SSL_V2_CT_X509_CERTIFICATE			0x01
#define SSL_V2_AT_MD5_WITH_RSA_ENCRYPTION	0x01

///////////////////////////////////////////////////////////////////////////////
// Типы используемых сообщений 
///////////////////////////////////////////////////////////////////////////////
#define SSL_V2_MT_ERROR						0
#define SSL_V2_MT_CLIENT_HELLO				1
#define SSL_V2_MT_CLIENT_MASTER_KEY			2
#define SSL_V2_MT_CLIENT_FINISHED			3
#define SSL_V2_MT_SERVER_HELLO				4
#define SSL_V2_MT_SERVER_VERIFY				5
#define SSL_V2_MT_SERVER_FINISHED			6
#define SSL_V2_MT_REQUEST_CERTIFICATE		7
#define SSL_V2_MT_CLIENT_CERTIFICATE		8

///////////////////////////////////////////////////////////////////////////////
// Коды ошибок 
///////////////////////////////////////////////////////////////////////////////
#define SSL_V2_PE_NO_CIPHER						0x0001
#define SSL_V2_PE_NO_CERTIFICATE				0x0002
#define SSL_V2_PE_BAD_CERTIFICATE				0x0004
#define SSL_V2_PE_UNSUPPORTED_CERTIFICATE_TYPE	0x0006

///////////////////////////////////////////////////////////////////////////////
// Сообщение об ошибке 
///////////////////////////////////////////////////////////////////////////////

// закодировать ошибку
size_t EncodeError(uint16_t errorCode, void* pvEncoded); 

// раскодировать ошибку
uint16_t DecodeError(const void* pvEncoded, size_t cbEncoded); 

///////////////////////////////////////////////////////////////////////////////
// Описание алгоритмов 
///////////////////////////////////////////////////////////////////////////////
typedef uint8_t V2CipherSpec[3];

// используемые алгоритмы
#define SSL_V2_CK_RC4_128_WITH_MD5				0x01,0x00,0x80
#define SSL_V2_CK_RC4_128_EXPORT40_WITH_MD5		0x02,0x00,0x80
#define SSL_V2_CK_RC2_128_CBC_WITH_MD5			0x03,0x00,0x80
#define SSL_V2_CK_RC2_128_CBC_EXPORT40_WITH_MD5	0x04,0x00,0x80
#define SSL_V2_CK_IDEA_128_CBC_WITH_MD5			0x05,0x00,0x80
#define SSL_V2_CK_DES_64_CBC_WITH_MD5			0x06,0x00,0x40
#define SSL_V2_CK_DES_192_EDE3_CBC_WITH_MD5		0x07,0x00,0xC0

///////////////////////////////////////////////////////////////////////////////
// Сообщения клиента
///////////////////////////////////////////////////////////////////////////////
struct V2ClientHello {						// передается в открытом виде
	uint16_t			clientVersion;		// номер версии протокола
	const V2CipherSpec*	pCipherSpecs;		// описание алгоритмов
	uint16_t			cCipherSpecs;		// число алгоритмов
	const uint8_t*		pbSessionID;		// идентификатор сеанса
	uint16_t			cbSessionID;		// размер идентификатора сеанса
	const uint8_t*		pbChallenge;		// случайные данные
	uint16_t			cbChallenge;		// размер случайных данных
};
struct V2ClientMasterKey {					// передается в открытом виде
	V2CipherSpec		cipherKind;			// описание алгоритма
	uint16_t			cCipherSpecs;		// число алгоритмов
	const uint8_t*		pbClearKey;			// открытая часть ключа
	uint16_t			cbClearKey;			// размер открытой части ключа
	const uint8_t*		pbEncryptedKey;		// зашифрованная часть ключа
	uint16_t			cbEncryptedKey;		// размер зашифрованной части ключа
	const uint8_t*		pbKeyArg;			// параметры алгоритма шифрования
	uint16_t			cbKeyArg;			// размер параметров алгоритма шифрования
};
struct V2ClientFinished {					// передается в зашифрованном виде
	const uint8_t*		pbConnectionID;		// зашифрованный идентификатор соединения 
	uint16_t			cbConnectionID;		// размер зашифрованного идентификатора соединения 
}; 
struct V2ClientCertificate {				// передается в зашифрованном виде
	uint8_t				certificateType;	// тип сертификата клиента
	const uint8_t*		pbCertificate;		// сертификат клиента
	uint16_t			cbCertificate;		// размер сертификата клиента
	const uint8_t*		pbResponse;			// ответные данные аутентификации
	uint16_t			cbResponse;			// размер ответных данных аутентификации
};

///////////////////////////////////////////////////////////////////////////////
// Сообщения клиента
///////////////////////////////////////////////////////////////////////////////
struct V2ServerHello {						// передается в открытом виде
	uint16_t			serverVersion;		// номер версии протокола
	uint8_t				sessionHit;			// признак распознавания сеанса
	uint8_t				certificateType;	// тип сертификата сервера
	const uint8_t*		pbCertificate;		// сертификат сервера 
	uint16_t			cbCertificate;		// размер сертификата сервера 
	const V2CipherSpec*	pCipherSpecs;		// описание алгоритмов
	uint16_t			cCipherSpecs;		// число алгоритмов
	const uint8_t*		pbConnectionID;		// идентификатор соединения 
	uint16_t			cbConnectionID;		// размер идентификатора соединения 
};
struct V2ServerVerify {						// передается в зашифрованном виде
	const uint8_t*		pbChallenge;		// зашифрованные случайные данные
	uint16_t			cbChallenge;		// размер зашифрованных случайных данных
}; 
struct V2ServerFinished {					// передается в зашифрованном виде
	const uint8_t*		pbSessionID;		// идентификатор сеанса
	uint16_t			cbSessionID;		// размер идентификатора сеанса
}; 
struct V2RequestCertificate {				// передается в зашифрованном виде
	uint8_t				authenticationType; // тип аутентификации клиента 
	const uint8_t*		pbChallenge;		// случайные данные
	uint16_t			cbChallenge;		// размер случайных данных
}; 
///////////////////////////////////////////////////////////////////////////////
// Кодирование сообщений 
///////////////////////////////////////////////////////////////////////////////

// закодировать сообщения 
size_t Encode(const V2ClientHello		* pMsg, void* pvEncoded); 
size_t Encode(const V2ClientMasterKey	* pMsg, void* pvEncoded); 
size_t Encode(const V2ClientFinished	* pMsg, void* pvEncoded); 
size_t Encode(const V2ClientCertificate * pMsg, void* pvEncoded); 
size_t Encode(const V2ServerHello		* pMsg, void* pvEncoded); 
size_t Encode(const V2ServerVerify		* pMsg, void* pvEncoded); 
size_t Encode(const V2ServerFinished	* pMsg, void* pvEncoded); 
size_t Encode(const V2RequestCertificate* pMsg, void* pvEncoded); 

// раскодировать сообщения 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ClientHello		* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ClientMasterKey	* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ClientFinished		* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ClientCertificate	* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ServerHello		* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ServerVerify		* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ServerFinished		* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2RequestCertificate	* pMsg); 

///////////////////////////////////////////////////////////////////////////////
// Используемый набор алгоритмов
///////////////////////////////////////////////////////////////////////////////
struct V2Cipher { virtual ~V2Cipher() {}

	// получить используемый набор алгоритмов
	static std::shared_ptr<V2Cipher> Create(const V2CipherSpec& cipherSpec); 

	// закодированное представление
	virtual const V2CipherSpec& Encoded() const = 0; 

	// сгенерировать параметры алгоритма
	virtual std::vector<uint8_t> GenerateParameters() const = 0; 
	// сгенерировать мастер-ключ
	virtual std::shared_ptr<ISecretKey> GenerateMasterKey(
		const void* pvParameters, size_t cbParameters) const = 0; 

	// создать ключ чтения для клиента (записи для сервера) 
	virtual std::shared_ptr<ISecretKey> CreateReadKey(
		const ISecretKey& masterKey, const void* pvChallenge, size_t cbChallenge, 
		const void* pvConnectionID, size_t cbConnectionID) const = 0; 

	// создать ключ записи для клиента (чтения для сервера) 
	virtual std::shared_ptr<ISecretKey> CreateWriteKey(
		const ISecretKey& masterKey, const void* pvChallenge, size_t cbChallenge, 
		const void* pvConnectionID, size_t cbConnectionID) const = 0; 

	// создать алгоритм хэширования 
	virtual std::shared_ptr<IHash> CreateHash() const = 0; 
	// создать алгоритм шифрования
	virtual std::shared_ptr<ICipher> CreateCipher(
		const void* pvParameters, size_t cbParameters) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Сохраненные данные сеанса
///////////////////////////////////////////////////////////////////////////////
class V2Session 
{ 
	// используемые алгоритмы
	private: std::shared_ptr<V2Cipher> _pCipher; bool _server;

	// параметры алгоритма и мастер-ключ
	private: std::vector<uint8_t> _parameters; std::shared_ptr<ISecretKey> _pMasterKey;  

	// сеансовые ключи шифрования
	private: std::shared_ptr<ISecretKey> _pReadKey; private: std::shared_ptr<ISecretKey> _pWriteKey;  
	
	// конструктор
	public: V2Session(const V2CipherSpec& cipherSpec, bool server) 
		
		// сохранить переданные параметры 
		: _pCipher(V2Cipher::Create(cipherSpec)), _server(server) {}

	// сгенерировать сеансовый ключ
	public: void GenerateMasterKey() { _parameters = _pCipher->GenerateParameters(); 
		
		// указать адрес параметров
		const void* pvParameters = (_parameters.size() != 0) ? &_parameters[0] : nullptr; 

		// сгенерировать мастер-ключ
		_pMasterKey = _pCipher->GenerateMasterKey(pvParameters, _parameters.size()); 
	}
	// параметры алгоритма 
	public: const std::vector<uint8_t>& Parameters() const { return _parameters; }

	// открытая часть мастер-ключа
	public: std::vector<uint8_t> ClearKey() const { return _pMasterKey->Salt(); } 
	// зашифрованная часть мастер-ключа 
	public: std::vector<uint8_t> EncryptKey(const void* pvCertificate, size_t cbCertificate) const
	{
		/* TODO */
	}
	// создать сеансовые ключи
	public: void CreateSessionKeys(const void* pvChallenge, size_t cbChallenge, 
		const void* pvConnectionID, size_t cbConnectionID)
	{
		if (_server)
		{
			// создать сеансовый ключ
			_pReadKey = _pCipher->CreateWriteKey(*_pMasterKey, 
				pvChallenge, cbChallenge, pvConnectionID, cbConnectionID
			);  
			// создать сеансовый ключ
			_pWriteKey = _pCipher->CreateReadKey(*_pMasterKey, 
				pvChallenge, cbChallenge, pvConnectionID, cbConnectionID
			);  
		}
		else {
			// создать сеансовый ключ
			_pReadKey = _pCipher->CreateReadKey(*_pMasterKey, 
				pvChallenge, cbChallenge, pvConnectionID, cbConnectionID
			);  
			// создать сеансовый ключ
			_pWriteKey = _pCipher->CreateWriteKey(*_pMasterKey, 
				pvChallenge, cbChallenge, pvConnectionID, cbConnectionID
			);  
		}
	}
	// захэшировать данные
	public: std::vector<uint8_t> HashData(const void* pvData, size_t cbData) const
	{
		// создать алгоритм хэширования
		std::shared_ptr<IHash> hash = _pCipher->CreateHash(); 

		// захэшировать данные
		return hash->HashData(pvData, cbData); 
	}
	// зашифровать данные
	public: std::vector<uint8_t> EncryptData(const void* pvData, size_t cbData) const
	{
		// указать адрес параметров
		const void* pvParameters = (_parameters.size() != 0) ? &_parameters[0] : nullptr; 

		// создать алгоритм шифрования 
		std::shared_ptr<ICipher> pCipher = _pCipher->CreateCipher(pvParameters, _parameters.size()); 

		// создать преобразование зашифрования
		std::shared_ptr<ITransform> pEncryption = pCipher->CreateEncryption(); 

		// зашифровать данные
		return pEncryption->TransformData(*_pWriteKey, pvData, (DWORD)cbData); 
	}
	// расшифровать данные
	public: std::vector<uint8_t> DecryptData(const void* pvData, size_t cbData) const
	{
		// указать адрес параметров
		const void* pvParameters = (_parameters.size() != 0) ? &_parameters[0] : nullptr; 

		// создать алгоритм шифрования 
		std::shared_ptr<ICipher> pCipher = _pCipher->CreateCipher(pvParameters, _parameters.size()); 

		// создать преобразование расшифрования
		std::shared_ptr<ITransform> pDecryption = pCipher->CreateDecryption(); 

		// зашифровать данные
		return pDecryption->TransformData(*_pReadKey, pvData, (DWORD)cbData); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Интерфейс клиента
///////////////////////////////////////////////////////////////////////////////
class V2Client { virtual ~V2Client() {}

	// начать протокол
	public: virtual std::vector<uint8_t> Start(const uint8_t* pbSessionID, uint16_t cbSessionID); 

	// обработчик сообщений
	public: std::vector<std::vector<uint8_t> > Dispatch(const void* pvData, size_t cbData);

	// обработка сообщений 
	protected: virtual std::vector<uint8_t> CreateMasterKey (const V2ServerHello       * pMsg); 
	protected: virtual std::vector<uint8_t> CreateFinish    (const V2ServerHello       * pMsg); 
	protected: virtual std::vector<uint8_t> ReplyCertificate(const V2RequestCertificate* pMsg); 

	// обработка сообщений 
	protected: virtual void OnServerVerify(const V2ServerVerify  * pMsg); 
	protected: virtual void OnServerFinish(const V2ServerFinished* pMsg); 

	// найти существующий сеанс
	protected: virtual V2Session* FindSession(const void* pbSessionID, size_t cbSessionID); 
	// поддерживаемые алгоритмы
	protected: virtual std::vector<V2CipherSpec> CipherSuites() const; 
	// сгенерировать случайные данные
	protected: virtual std::vector<uint8_t> GenerateChallenge() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Интерфейс сервера
///////////////////////////////////////////////////////////////////////////////
class V2Server { virtual ~V2Server() {}

	// обработчик сообщений
	public: std::vector<std::vector<uint8_t> > Dispatch(const void* pvData, size_t cbData);

	// обработка сообщений 
	protected: virtual std::vector<uint8_t> CreateHello       (const V2ClientHello    * pMsg); 
	protected: virtual std::vector<uint8_t> CreateVerify      (const V2ClientMasterKey* pMsg); 
	protected: virtual std::vector<uint8_t> CreateFinish      (const V2ClientFinished * pMsg); 
	protected: virtual std::vector<uint8_t> RequestCertificate(const V2ClientFinished * pMsg); 

	// обработка сообщений 
	protected: virtual void OnClientCertificate(const V2ClientCertificate* pMsg); 
	protected: virtual void OnClientFinish     (const V2ClientFinished   * pMsg); 

	// найти существующий сеанс
	protected: virtual V2Session* FindSession(const void* pbSessionID, size_t cbSessionID); 
	// поддерживаемые алгоритмы
	protected: virtual std::vector<V2CipherSpec> CipherSuites() const; 
	// сгенерировать случайные данные
	protected: virtual std::vector<uint8_t> GenerateChallenge() const; 
}; 

}}

