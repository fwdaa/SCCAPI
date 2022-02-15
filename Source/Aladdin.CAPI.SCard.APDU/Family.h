namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU
{
///////////////////////////////////////////////////////////////////////////
// ��������� �����-����
///////////////////////////////////////////////////////////////////////////
public interface class ITokenFamily
{
	// ��������� �������������� ATR
	bool Contains(array<BYTE>^ atr); 

    // ����������� �������
	array<String^>^ EnumerateApplets(PCSC::ReaderSession^ session, array<BYTE>^ atr); 
};
///////////////////////////////////////////////////////////////////////////
// ��������� eToken
///////////////////////////////////////////////////////////////////////////
public ref class ETFamily : ITokenFamily
{
	// ��������� ���������
	public: static initonly ETFamily^ Instance = gcnew ETFamily(); 

	// ��������� �������������� ATR
	public: virtual bool Contains(array<BYTE>^ atr); 

    // ����������� �������
	public: virtual array<String^>^ EnumerateApplets(PCSC::ReaderSession^ session, array<BYTE>^ atr)
	{
		// �������������� ������ ���� ������
		return gcnew array<String^> { "Pro" }; 
	}
};
///////////////////////////////////////////////////////////////////////////
// ��������� eToken JavaCard � JaCarta
///////////////////////////////////////////////////////////////////////////
public ref class JCFamily : ITokenFamily
{
	// ��������� ���������
	public: static initonly JCFamily^ Instance = gcnew JCFamily(); 

	// ��������� �������������� ATR
	public: virtual bool Contains(array<BYTE>^ atr); 

	// ������� ������
	public: void SelectApplet(PCSC::ReaderSession^ session, array<BYTE>^ atr, String^ applet); 

    // ����������� �������
	public: virtual array<String^>^ EnumerateApplets(PCSC::ReaderSession^ session, array<BYTE>^ atr); 
};
}}}}

