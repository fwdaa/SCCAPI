namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { 
	
namespace DataStore
{
	// функция определения раскладки клавиатуры
	[DllImport("jcPKCS11ds.dll", CallingConvention = CallingConvention::Cdecl,
		CharSet = CharSet::Auto, ExactSpelling = true)]
	extern UInt32 C_GetFunctionList([Out] IntPtr% ppFunctionList);

    ///////////////////////////////////////////////////////////////////////////
    // Вызов методов из внешних модулей
    ///////////////////////////////////////////////////////////////////////////
	public ref class NativeAPI : PKCS11::API
    {
        // получить список функций
		public: virtual PKCS11::API::CK_GETFUNCTIONLIST^ GetFunctionList() override
		{
			// получить список функций
			return gcnew PKCS11::API::CK_GETFUNCTIONLIST(C_GetFunctionList); 
		}
    };
}
namespace Pro
{
	// функция определения раскладки клавиатуры
	[DllImport("etPKCS11.dll", CallingConvention = CallingConvention::Cdecl,
		CharSet = CharSet::Auto, ExactSpelling = true)]
	extern UInt32 C_GetFunctionList([Out] IntPtr% ppFunctionList);

    // функция получения списка функций
    [DllImport("etPKCS11.dll", CallingConvention = CallingConvention::Cdecl,
		CharSet=CharSet::Auto, ExactSpelling = true)]
    extern UInt32 ETC_GetFunctionListEx([Out] IntPtr% ppFunctionList);

    ///////////////////////////////////////////////////////////////////////////
    // Вызов методов из внешних модулей
    ///////////////////////////////////////////////////////////////////////////
	public ref class NativeAPI : PKCS11::API
    {
        // получить список функций
		public: virtual PKCS11::API::CK_GETFUNCTIONLIST^ GetFunctionList() override
		{
			// получить список функций
			return gcnew PKCS11::API::CK_GETFUNCTIONLIST(C_GetFunctionList); 
		}
    };
}
namespace Laser
{
	// функция определения раскладки клавиатуры
	[DllImport("asepkcs.dll", CallingConvention = CallingConvention::Cdecl,
		CharSet = CharSet::Auto, ExactSpelling = true)]
	extern UInt32 C_GetFunctionList([Out] IntPtr% ppFunctionList);

	[DllImport("asepkcs.dll", CallingConvention = CallingConvention::Cdecl,
		CharSet=CharSet::Auto, ExactSpelling = true)]
	extern UInt32 C_Control([In] UInt32 slotID, [In] UInt32 command, 
		[In] IntPtr buffer, [In] IntPtr pBufferSize
	);
    ///////////////////////////////////////////////////////////////////////////
    // Вызов методов из внешних модулей
    ///////////////////////////////////////////////////////////////////////////
	public ref class NativeAPI : PKCS11::API
    {
        // получить список функций
		public: virtual PKCS11::API::CK_GETFUNCTIONLIST^ GetFunctionList() override
		{
			// получить список функций
			return gcnew PKCS11::API::CK_GETFUNCTIONLIST(C_GetFunctionList); 
		}
    };
}
}}}}
