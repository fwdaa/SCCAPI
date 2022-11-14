#pragma once
#include "crypto.h"

namespace Crypto { namespace SSL { 

///////////////////////////////////////////////////////////////////////////////
// ��� ����������� � �������������� �������
///////////////////////////////////////////////////////////////////////////////
#define SSL_V2_CT_X509_CERTIFICATE			0x01
#define SSL_V2_AT_MD5_WITH_RSA_ENCRYPTION	0x01

///////////////////////////////////////////////////////////////////////////////
// ���� ������������ ��������� 
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
// ���� ������ 
///////////////////////////////////////////////////////////////////////////////
#define SSL_V2_PE_NO_CIPHER						0x0001
#define SSL_V2_PE_NO_CERTIFICATE				0x0002
#define SSL_V2_PE_BAD_CERTIFICATE				0x0004
#define SSL_V2_PE_UNSUPPORTED_CERTIFICATE_TYPE	0x0006

///////////////////////////////////////////////////////////////////////////////
// ��������� �� ������ 
///////////////////////////////////////////////////////////////////////////////

// ������������ ������
size_t EncodeError(uint16_t errorCode, void* pvEncoded); 

// ������������� ������
uint16_t DecodeError(const void* pvEncoded, size_t cbEncoded); 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
typedef uint8_t V2CipherSpec[3];

// ������������ ���������
#define SSL_V2_CK_RC4_128_WITH_MD5				0x01,0x00,0x80
#define SSL_V2_CK_RC4_128_EXPORT40_WITH_MD5		0x02,0x00,0x80
#define SSL_V2_CK_RC2_128_CBC_WITH_MD5			0x03,0x00,0x80
#define SSL_V2_CK_RC2_128_CBC_EXPORT40_WITH_MD5	0x04,0x00,0x80
#define SSL_V2_CK_IDEA_128_CBC_WITH_MD5			0x05,0x00,0x80
#define SSL_V2_CK_DES_64_CBC_WITH_MD5			0x06,0x00,0x40
#define SSL_V2_CK_DES_192_EDE3_CBC_WITH_MD5		0x07,0x00,0xC0

///////////////////////////////////////////////////////////////////////////////
// ��������� �������
///////////////////////////////////////////////////////////////////////////////
struct V2ClientHello {						// ���������� � �������� ����
	uint16_t			clientVersion;		// ����� ������ ���������
	const V2CipherSpec*	pCipherSpecs;		// �������� ����������
	uint16_t			cCipherSpecs;		// ����� ����������
	const uint8_t*		pbSessionID;		// ������������� ������
	uint16_t			cbSessionID;		// ������ �������������� ������
	const uint8_t*		pbChallenge;		// ��������� ������
	uint16_t			cbChallenge;		// ������ ��������� ������
};
struct V2ClientMasterKey {					// ���������� � �������� ����
	V2CipherSpec		cipherKind;			// �������� ���������
	uint16_t			cCipherSpecs;		// ����� ����������
	const uint8_t*		pbClearKey;			// �������� ����� �����
	uint16_t			cbClearKey;			// ������ �������� ����� �����
	const uint8_t*		pbEncryptedKey;		// ������������� ����� �����
	uint16_t			cbEncryptedKey;		// ������ ������������� ����� �����
	const uint8_t*		pbKeyArg;			// ��������� ��������� ����������
	uint16_t			cbKeyArg;			// ������ ���������� ��������� ����������
};
struct V2ClientFinished {					// ���������� � ������������� ����
	const uint8_t*		pbConnectionID;		// ������������� ������������� ���������� 
	uint16_t			cbConnectionID;		// ������ �������������� �������������� ���������� 
}; 
struct V2ClientCertificate {				// ���������� � ������������� ����
	uint8_t				certificateType;	// ��� ����������� �������
	const uint8_t*		pbCertificate;		// ���������� �������
	uint16_t			cbCertificate;		// ������ ����������� �������
	const uint8_t*		pbResponse;			// �������� ������ ��������������
	uint16_t			cbResponse;			// ������ �������� ������ ��������������
};

///////////////////////////////////////////////////////////////////////////////
// ��������� �������
///////////////////////////////////////////////////////////////////////////////
struct V2ServerHello {						// ���������� � �������� ����
	uint16_t			serverVersion;		// ����� ������ ���������
	uint8_t				sessionHit;			// ������� ������������� ������
	uint8_t				certificateType;	// ��� ����������� �������
	const uint8_t*		pbCertificate;		// ���������� ������� 
	uint16_t			cbCertificate;		// ������ ����������� ������� 
	const V2CipherSpec*	pCipherSpecs;		// �������� ����������
	uint16_t			cCipherSpecs;		// ����� ����������
	const uint8_t*		pbConnectionID;		// ������������� ���������� 
	uint16_t			cbConnectionID;		// ������ �������������� ���������� 
};
struct V2ServerVerify {						// ���������� � ������������� ����
	const uint8_t*		pbChallenge;		// ������������� ��������� ������
	uint16_t			cbChallenge;		// ������ ������������� ��������� ������
}; 
struct V2ServerFinished {					// ���������� � ������������� ����
	const uint8_t*		pbSessionID;		// ������������� ������
	uint16_t			cbSessionID;		// ������ �������������� ������
}; 
struct V2RequestCertificate {				// ���������� � ������������� ����
	uint8_t				authenticationType; // ��� �������������� ������� 
	const uint8_t*		pbChallenge;		// ��������� ������
	uint16_t			cbChallenge;		// ������ ��������� ������
}; 
///////////////////////////////////////////////////////////////////////////////
// ����������� ��������� 
///////////////////////////////////////////////////////////////////////////////

// ������������ ��������� 
size_t Encode(const V2ClientHello		* pMsg, void* pvEncoded); 
size_t Encode(const V2ClientMasterKey	* pMsg, void* pvEncoded); 
size_t Encode(const V2ClientFinished	* pMsg, void* pvEncoded); 
size_t Encode(const V2ClientCertificate * pMsg, void* pvEncoded); 
size_t Encode(const V2ServerHello		* pMsg, void* pvEncoded); 
size_t Encode(const V2ServerVerify		* pMsg, void* pvEncoded); 
size_t Encode(const V2ServerFinished	* pMsg, void* pvEncoded); 
size_t Encode(const V2RequestCertificate* pMsg, void* pvEncoded); 

// ������������� ��������� 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ClientHello		* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ClientMasterKey	* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ClientFinished		* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ClientCertificate	* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ServerHello		* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ServerVerify		* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2ServerFinished		* pMsg); 
size_t Decode(const void* pvEncoded, size_t cbEncoded, V2RequestCertificate	* pMsg); 

///////////////////////////////////////////////////////////////////////////////
// ������������ ����� ����������
///////////////////////////////////////////////////////////////////////////////
struct V2Cipher { virtual ~V2Cipher() {}

	// �������� ������������ ����� ����������
	static std::shared_ptr<V2Cipher> Create(const V2CipherSpec& cipherSpec); 

	// �������������� �������������
	virtual const V2CipherSpec& Encoded() const = 0; 

	// ������������� ��������� ���������
	virtual std::vector<uint8_t> GenerateParameters() const = 0; 
	// ������������� ������-����
	virtual std::shared_ptr<ISecretKey> GenerateMasterKey(
		const void* pvParameters, size_t cbParameters) const = 0; 

	// ������� ���� ������ ��� ������� (������ ��� �������) 
	virtual std::shared_ptr<ISecretKey> CreateReadKey(
		const ISecretKey& masterKey, const void* pvChallenge, size_t cbChallenge, 
		const void* pvConnectionID, size_t cbConnectionID) const = 0; 

	// ������� ���� ������ ��� ������� (������ ��� �������) 
	virtual std::shared_ptr<ISecretKey> CreateWriteKey(
		const ISecretKey& masterKey, const void* pvChallenge, size_t cbChallenge, 
		const void* pvConnectionID, size_t cbConnectionID) const = 0; 

	// ������� �������� ����������� 
	virtual std::shared_ptr<IHash> CreateHash() const = 0; 
	// ������� �������� ����������
	virtual std::shared_ptr<ICipher> CreateCipher(
		const void* pvParameters, size_t cbParameters) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ ������
///////////////////////////////////////////////////////////////////////////////
class V2Session 
{ 
	// ������������ ���������
	private: std::shared_ptr<V2Cipher> _pCipher; bool _server;

	// ��������� ��������� � ������-����
	private: std::vector<uint8_t> _parameters; std::shared_ptr<ISecretKey> _pMasterKey;  

	// ��������� ����� ����������
	private: std::shared_ptr<ISecretKey> _pReadKey; private: std::shared_ptr<ISecretKey> _pWriteKey;  
	
	// �����������
	public: V2Session(const V2CipherSpec& cipherSpec, bool server) 
		
		// ��������� ���������� ��������� 
		: _pCipher(V2Cipher::Create(cipherSpec)), _server(server) {}

	// ������������� ��������� ����
	public: void GenerateMasterKey() { _parameters = _pCipher->GenerateParameters(); 
		
		// ������� ����� ����������
		const void* pvParameters = (_parameters.size() != 0) ? &_parameters[0] : nullptr; 

		// ������������� ������-����
		_pMasterKey = _pCipher->GenerateMasterKey(pvParameters, _parameters.size()); 
	}
	// ��������� ��������� 
	public: const std::vector<uint8_t>& Parameters() const { return _parameters; }

	// �������� ����� ������-�����
	public: std::vector<uint8_t> ClearKey() const { return _pMasterKey->Salt(); } 
	// ������������� ����� ������-����� 
	public: std::vector<uint8_t> EncryptKey(const void* pvCertificate, size_t cbCertificate) const
	{
		/* TODO */
	}
	// ������� ��������� �����
	public: void CreateSessionKeys(const void* pvChallenge, size_t cbChallenge, 
		const void* pvConnectionID, size_t cbConnectionID)
	{
		if (_server)
		{
			// ������� ��������� ����
			_pReadKey = _pCipher->CreateWriteKey(*_pMasterKey, 
				pvChallenge, cbChallenge, pvConnectionID, cbConnectionID
			);  
			// ������� ��������� ����
			_pWriteKey = _pCipher->CreateReadKey(*_pMasterKey, 
				pvChallenge, cbChallenge, pvConnectionID, cbConnectionID
			);  
		}
		else {
			// ������� ��������� ����
			_pReadKey = _pCipher->CreateReadKey(*_pMasterKey, 
				pvChallenge, cbChallenge, pvConnectionID, cbConnectionID
			);  
			// ������� ��������� ����
			_pWriteKey = _pCipher->CreateWriteKey(*_pMasterKey, 
				pvChallenge, cbChallenge, pvConnectionID, cbConnectionID
			);  
		}
	}
	// ������������ ������
	public: std::vector<uint8_t> HashData(const void* pvData, size_t cbData) const
	{
		// ������� �������� �����������
		std::shared_ptr<IHash> hash = _pCipher->CreateHash(); 

		// ������������ ������
		return hash->HashData(pvData, cbData); 
	}
	// ����������� ������
	public: std::vector<uint8_t> EncryptData(const void* pvData, size_t cbData) const
	{
		// ������� ����� ����������
		const void* pvParameters = (_parameters.size() != 0) ? &_parameters[0] : nullptr; 

		// ������� �������� ���������� 
		std::shared_ptr<ICipher> pCipher = _pCipher->CreateCipher(pvParameters, _parameters.size()); 

		// ������� �������������� ������������
		std::shared_ptr<ITransform> pEncryption = pCipher->CreateEncryption(); 

		// ����������� ������
		return pEncryption->TransformData(*_pWriteKey, pvData, (DWORD)cbData); 
	}
	// ������������ ������
	public: std::vector<uint8_t> DecryptData(const void* pvData, size_t cbData) const
	{
		// ������� ����� ����������
		const void* pvParameters = (_parameters.size() != 0) ? &_parameters[0] : nullptr; 

		// ������� �������� ���������� 
		std::shared_ptr<ICipher> pCipher = _pCipher->CreateCipher(pvParameters, _parameters.size()); 

		// ������� �������������� �������������
		std::shared_ptr<ITransform> pDecryption = pCipher->CreateDecryption(); 

		// ����������� ������
		return pDecryption->TransformData(*_pReadKey, pvData, (DWORD)cbData); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� �������
///////////////////////////////////////////////////////////////////////////////
class V2Client { virtual ~V2Client() {}

	// ������ ��������
	public: virtual std::vector<uint8_t> Start(const uint8_t* pbSessionID, uint16_t cbSessionID); 

	// ���������� ���������
	public: std::vector<std::vector<uint8_t> > Dispatch(const void* pvData, size_t cbData);

	// ��������� ��������� 
	protected: virtual std::vector<uint8_t> CreateMasterKey (const V2ServerHello       * pMsg); 
	protected: virtual std::vector<uint8_t> CreateFinish    (const V2ServerHello       * pMsg); 
	protected: virtual std::vector<uint8_t> ReplyCertificate(const V2RequestCertificate* pMsg); 

	// ��������� ��������� 
	protected: virtual void OnServerVerify(const V2ServerVerify  * pMsg); 
	protected: virtual void OnServerFinish(const V2ServerFinished* pMsg); 

	// ����� ������������ �����
	protected: virtual V2Session* FindSession(const void* pbSessionID, size_t cbSessionID); 
	// �������������� ���������
	protected: virtual std::vector<V2CipherSpec> CipherSuites() const; 
	// ������������� ��������� ������
	protected: virtual std::vector<uint8_t> GenerateChallenge() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� �������
///////////////////////////////////////////////////////////////////////////////
class V2Server { virtual ~V2Server() {}

	// ���������� ���������
	public: std::vector<std::vector<uint8_t> > Dispatch(const void* pvData, size_t cbData);

	// ��������� ��������� 
	protected: virtual std::vector<uint8_t> CreateHello       (const V2ClientHello    * pMsg); 
	protected: virtual std::vector<uint8_t> CreateVerify      (const V2ClientMasterKey* pMsg); 
	protected: virtual std::vector<uint8_t> CreateFinish      (const V2ClientFinished * pMsg); 
	protected: virtual std::vector<uint8_t> RequestCertificate(const V2ClientFinished * pMsg); 

	// ��������� ��������� 
	protected: virtual void OnClientCertificate(const V2ClientCertificate* pMsg); 
	protected: virtual void OnClientFinish     (const V2ClientFinished   * pMsg); 

	// ����� ������������ �����
	protected: virtual V2Session* FindSession(const void* pbSessionID, size_t cbSessionID); 
	// �������������� ���������
	protected: virtual std::vector<V2CipherSpec> CipherSuites() const; 
	// ������������� ��������� ������
	protected: virtual std::vector<uint8_t> GenerateChallenge() const; 
}; 

}}

