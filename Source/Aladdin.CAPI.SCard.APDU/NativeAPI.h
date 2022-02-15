namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU { 
	
namespace DataStore
{
	// ������� ����������� ��������� ����������
	[DllImport("jcPKCS11ds.dll", CallingConvention = CallingConvention::Cdecl,
		CharSet = CharSet::Auto, ExactSpelling = true)]
	extern UInt32 C_GetFunctionList([Out] IntPtr% ppFunctionList);

    ///////////////////////////////////////////////////////////////////////////
    // ����� ������� �� ������� �������
    ///////////////////////////////////////////////////////////////////////////
	public ref class NativeAPI : PKCS11::API
    {
        // �������� ������ �������
		public: virtual PKCS11::API::CK_GETFUNCTIONLIST^ GetFunctionList() override
		{
			// �������� ������ �������
			return gcnew PKCS11::API::CK_GETFUNCTIONLIST(C_GetFunctionList); 
		}
    };
}
namespace Pro
{
	// ������� ����������� ��������� ����������
	[DllImport("etPKCS11.dll", CallingConvention = CallingConvention::Cdecl,
		CharSet = CharSet::Auto, ExactSpelling = true)]
	extern UInt32 C_GetFunctionList([Out] IntPtr% ppFunctionList);

    // ������� ��������� ������ �������
    [DllImport("etPKCS11.dll", CallingConvention = CallingConvention::Cdecl,
		CharSet=CharSet::Auto, ExactSpelling = true)]
    extern UInt32 ETC_GetFunctionListEx([Out] IntPtr% ppFunctionList);

    ///////////////////////////////////////////////////////////////////////////
    // ����� ������� �� ������� �������
    ///////////////////////////////////////////////////////////////////////////
	public ref class NativeAPI : PKCS11::API
    {
        // �������� ������ �������
		public: virtual PKCS11::API::CK_GETFUNCTIONLIST^ GetFunctionList() override
		{
			// �������� ������ �������
			return gcnew PKCS11::API::CK_GETFUNCTIONLIST(C_GetFunctionList); 
		}
    };
}
namespace Laser
{
	// ������� ����������� ��������� ����������
	[DllImport("asepkcs.dll", CallingConvention = CallingConvention::Cdecl,
		CharSet = CharSet::Auto, ExactSpelling = true)]
	extern UInt32 C_GetFunctionList([Out] IntPtr% ppFunctionList);

	[DllImport("asepkcs.dll", CallingConvention = CallingConvention::Cdecl,
		CharSet=CharSet::Auto, ExactSpelling = true)]
	extern UInt32 C_Control([In] UInt32 slotID, [In] UInt32 command, 
		[In] IntPtr buffer, [In] IntPtr pBufferSize
	);
    ///////////////////////////////////////////////////////////////////////////
    // ����� ������� �� ������� �������
    ///////////////////////////////////////////////////////////////////////////
	public ref class NativeAPI : PKCS11::API
    {
        // �������� ������ �������
		public: virtual PKCS11::API::CK_GETFUNCTIONLIST^ GetFunctionList() override
		{
			// �������� ������ �������
			return gcnew PKCS11::API::CK_GETFUNCTIONLIST(C_GetFunctionList); 
		}
    };
}
}}}}
