namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU
{
///////////////////////////////////////////////////////////////////////////
// Семейство смарт-карт
///////////////////////////////////////////////////////////////////////////
public interface class ITokenFamily
{
	// проверить принадлежность ATR
	bool Contains(array<BYTE>^ atr); 

    // перечислить апплеты
	array<String^>^ EnumerateApplets(PCSC::ReaderSession^ session, array<BYTE>^ atr); 
};
///////////////////////////////////////////////////////////////////////////
// Семейство eToken
///////////////////////////////////////////////////////////////////////////
public ref class ETFamily : ITokenFamily
{
	// экземпляр семейства
	public: static initonly ETFamily^ Instance = gcnew ETFamily(); 

	// проверить принадлежность ATR
	public: virtual bool Contains(array<BYTE>^ atr); 

    // перечислить апплеты
	public: virtual array<String^>^ EnumerateApplets(PCSC::ReaderSession^ session, array<BYTE>^ atr)
	{
		// поддерживается только один апплет
		return gcnew array<String^> { "Pro" }; 
	}
};
///////////////////////////////////////////////////////////////////////////
// Семейства eToken JavaCard и JaCarta
///////////////////////////////////////////////////////////////////////////
public ref class JCFamily : ITokenFamily
{
	// экземпляр семейства
	public: static initonly JCFamily^ Instance = gcnew JCFamily(); 

	// проверить принадлежность ATR
	public: virtual bool Contains(array<BYTE>^ atr); 

	// выбрать апплет
	public: void SelectApplet(PCSC::ReaderSession^ session, array<BYTE>^ atr, String^ applet); 

    // перечислить апплеты
	public: virtual array<String^>^ EnumerateApplets(PCSC::ReaderSession^ session, array<BYTE>^ atr); 
};
}}}}

