#include <windows.h>
#include "TraceETW.h"
#include <tdh.h>
#include <wbemidl.h>
#include <in6addr.h>

///////////////////////////////////////////////////////////////////////////////
// ����������� ���������� C++
///////////////////////////////////////////////////////////////////////////////
#include <stdexcept>    // std::runtime_error
#include <memory>       // std::shared_ptr
#include <string>       // std::string, std::wstring
#include <vector>       // std::vector
#include <map>          // std::map
#include <sstream>      // std::wostringstream
#include <ios>          // std::dec, std::hex, std::fixed

namespace ETW {

///////////////////////////////////////////////////////////////////////////////
// ����������
///////////////////////////////////////////////////////////////////////////////
class Exception : public std::runtime_error
{
    // ��� � �������� ������
    private: HRESULT _status; std::string _strMessage; 

    // ��������� ����������
    public: static __declspec(noreturn) void Throw(HRESULT status) { throw Exception(status); }
    // ��������� ����������
    public: static __declspec(noreturn) void Throw(HRESULT, IUnknown*, REFIID);

    // �����������
    public: Exception(HRESULT status, IErrorInfo* pErrorInfo = nullptr); 

    // �������� ������
    public: virtual const char* what() const { return _strMessage.c_str(); }  
    // ��� ������
    public: HRESULT status() const { return _status; }
};

inline __declspec(noreturn) void ThrowBadData()
{
    // ��������� ����������
    Exception::Throw(HRESULT_FROM_WIN32(ERROR_INVALID_DATA)); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ���
///////////////////////////////////////////////////////////////////////////////
struct BasicType : IBasicType
{
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const = 0;

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const = 0; 
    public: virtual USHORT OutputType() const = 0; 

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const {}
};
 
///////////////////////////////////////////////////////////////////////////////
// ��������� ���
///////////////////////////////////////////////////////////////////////////////
class BooleanType : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_BOOLEAN; }
    // ������ �������������� �������
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_BOOLEAN; }

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_BOOL; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return FALSE; }

    // �������� ������ ��������
    public: virtual size_t GetSize(const ETW::IContainer&, const void*, size_t) const override; 
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void*, size_t) const override; 

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ��� �����
///////////////////////////////////////////////////////////////////////////////
class Int8Type : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_INT8; } 

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_I1; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� ������
    public: virtual USHORT InputType() const override { return TDH_INTYPE_INT8; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(CHAR)) ThrowBadData(); return sizeof(CHAR); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // ����������� ��������
        memcpy(&V_I1(&var), pvData, cbData); return var; 
    }
    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // �������� �������� �������� ��� �����
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // ������� ��������� ������������� ��������
            BYTE value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // ������� ������� �������
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class UInt8Type : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_UINT8; } 

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_UI1; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� ������
    public: virtual USHORT InputType() const override { return TDH_INTYPE_UINT8; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(BYTE)) ThrowBadData(); return sizeof(BYTE); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // ����������� ��������
        memcpy(&V_UI1(&var), pvData, cbData); return var; 
    }
    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // �������� �������� �������� ��� �����
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // ������� ��������� ������������� ��������
            BYTE value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // ������� ������� �������
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class Int16Type : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_INT16; } 

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_I2; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� ������
    public: virtual USHORT InputType() const override { return TDH_INTYPE_INT16; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(SHORT)) ThrowBadData(); return sizeof(SHORT); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // ����������� ��������
        memcpy(&V_I2(&var), pvData, cbData); return var; 
    }
    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // �������� �������� �������� ��� �����
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // ������� ��������� ������������� ��������
            USHORT value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // ������� ������� �������
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class UInt16Type : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_UINT16; } 

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_UI2; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� ������
    public: virtual USHORT InputType() const override { return TDH_INTYPE_UINT16; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(USHORT)) ThrowBadData(); return sizeof(USHORT); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // ����������� ��������
        memcpy(&V_UI2(&var), pvData, cbData); 
        
        // ��� ������ �����
        if (OutputType() == TDH_OUTTYPE_PORT)
        {
             // �������� ������� ���������� ������
            V_UI2(&var) = MAKEWORD(HIWORD(V_UI2(&var)), LOWORD(V_UI2(&var))); 
        }
        return var; 
    }
    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // �������� �������� �������� ��� �����
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // ������� ��������� ������������� ��������
            USHORT value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // ������� ������� �������
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class Int32Type : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_INT16; } 

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_I4; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� ������
    public: virtual USHORT InputType() const override { return TDH_INTYPE_INT32; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(LONG)) ThrowBadData(); return sizeof(LONG); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // ����������� ��������
        memcpy(&V_I4(&var), pvData, cbData); return var; 
    }
    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // �������� �������� �������� ��� �����
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // ������� ��������� ������������� ��������
            ULONG value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // ������� ������� �������
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class UInt32Type : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_UINT32; } 

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_UI4; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� ������
    public: virtual USHORT InputType() const override { return TDH_INTYPE_UINT32; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(ULONG)) ThrowBadData(); return sizeof(ULONG); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // ����������� ��������
        memcpy(&V_UI4(&var), pvData, cbData); return var; 
    }
    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // �������� �������� �������� ��� �����
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // ������� ��������� ������������� ��������
            ULONG value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // ������� ������� �������
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class Int64Type : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_INT64; } 

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_I8; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� ������
    public: virtual USHORT InputType() const override { return TDH_INTYPE_INT64; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(LONGLONG)) ThrowBadData(); return sizeof(LONGLONG); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // ����������� ��������
        memcpy(&V_I8(&var), pvData, cbData); return var; 
    }
    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // �������� �������� �������� ��� �����
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // ������� ��������� ������������� ��������
            ULONGLONG value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // ������� ������� �������
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class UInt64Type : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_UINT64; } 

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_UI8; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� ������
    public: virtual USHORT InputType() const override { return TDH_INTYPE_UINT64; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(ULONGLONG)) ThrowBadData(); return sizeof(ULONGLONG); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // ����������� ��������
        memcpy(&V_UI8(&var), pvData, cbData); return var; 
    }
    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // �������� �������� �������� ��� �����
        if (const IValueMap* pValueMap = GetValueMap())
        {
            // ������� ��������� ������������� ��������
            ULONGLONG value; memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
        }
        // ������� ������� �������
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class FloatType : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_FLOAT; } 
    // ������ �������������� ��������
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_FLOAT; }

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_R4; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� �������� 
    public: virtual USHORT InputType() const override { return TDH_INTYPE_FLOAT; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(FLOAT)) ThrowBadData(); return sizeof(FLOAT); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // ����������� ��������
        memcpy(&V_R4(&var), pvData, cbData); return var; 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override
    {
        // �������� ��������� �������������
        stream << std::fixed << V_R4(&value);
    }
};

class DoubleType : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_DOUBLE; } 
    // ������ �������������� ��������
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_DOUBLE; }

    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_R8; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� �������� 
    public: virtual USHORT InputType() const override { return TDH_INTYPE_DOUBLE; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(DOUBLE)) ThrowBadData(); return sizeof(DOUBLE); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 
    
        // ����������� ��������
        memcpy(&V_R8(&var), pvData, cbData); return var; 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override
    {
        // �������� ��������� �������������
        stream << std::fixed << V_R8(&value);
    }
};

///////////////////////////////////////////////////////////////////////////////
// ��� ��������� ��� ����� ����������� ���������
///////////////////////////////////////////////////////////////////////////////
class PointerType : public BasicType
{
    // �����������
    public: PointerType(size_t pointerSize) 
        
        // ��������� ���������� ���������
        : _pointerSize(pointerSize) {} private: size_t _pointerSize; 

    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override
    {
        // ���������� ��� ��������
        return (InputType() == TDH_INTYPE_POINTER) ? TYPE_POINTER : TYPE_SIZE_T;  
    }
    // COM-��� ��������
    public: virtual VARTYPE VariantType() const override
    {
        // COM-��� ��������
        return (VARTYPE)((_pointerSize == 4) ? VT_UI4 : VT_UI8); 
    }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return TRUE; }

    // ���������� ��� �������� 
    public: virtual USHORT InputType() const override 
    { 
        // ���������� ��� �������� 
        return (VARTYPE)((_pointerSize == 4) ? TDH_INTYPE_UINT32 : TDH_INTYPE_UINT64); 
    }
    // �������� ������ ��������
    public: virtual size_t GetSize(const struct IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < _pointerSize) ThrowBadData(); return _pointerSize; 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ���������������� ����������
        VARIANT var; ::VariantInit(&var); V_VT(&var) = VariantType(); 

        if (_pointerSize == 4)
        {
            // ����������� ��������
            memcpy(&V_UI4(&var), pvData, cbData); return var; 
        }
        else {
            // ����������� ��������
            memcpy(&V_UI8(&var), pvData, cbData); return var; 
        }
    }
    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override
    {
        // �������� �������� �������� ��� �����
        if (const IValueMap* pValueMap = GetValueMap())
        {
            if (_pointerSize == 4) { ULONG value; 
            
                // ������� ��������� ������������� ��������
                memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
            }
            else { ULONGLONG value; 

                // ������� ��������� ������������� ��������
                memcpy(&value, pvData, cbData); return pValueMap->ToString(value); 
            }
        }
        // ������� ������� �������
        return BasicType::ToString(parent, pvData, cbData); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};
 
///////////////////////////////////////////////////////////////////////////////
// ��� �����
///////////////////////////////////////////////////////////////////////////////
class StringType : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_STRING; }

    // �OM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_BSTR; } 
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return FALSE; }  

    // �������� ������ ��������
    public: virtual size_t GetSize(const ETW::IContainer&, const void*, size_t) const override; 
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void*, size_t) const override; 

    // ���������� ������ ������
    protected: virtual size_t GetLength(const ETW::IContainer*) const { return SIZE_MAX; } 

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer& parent, const void* pvData, size_t cbData) const override; 
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ��� �������
///////////////////////////////////////////////////////////////////////////////
class DateTimeType : public BasicType
{
    // �����������
    public: DateTimeType(); private: ISWbemDateTime* _pConvert;
    // ����������
    public: virtual ~DateTimeType() { if (_pConvert) _pConvert->Release(); }

    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_DATE; }  

    // �OM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_DATE; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return FALSE; }

    // �������� ������ ��������
    public: virtual size_t GetSize(const IContainer&, const void*, size_t) const override; 
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void*, size_t) const override; 

    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 

    // ������������� ������
    protected: VARIANT DecodeString(BSTR bstrString) const; 
};
 
class CimDateTimeType : public DateTimeType
{
    // ���������� ��� �������� 
    public: virtual USHORT InputType() const override { return Decoder().InputType(); }
    // �������� ������ ��������
    public: virtual size_t GetSize(const IContainer& parent, const void* pvData, size_t cbRemaining) const override
    {
        // �������� ������ ��������
        return Decoder().GetSize(parent, pvData, cbRemaining); 
    }
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void* pvData, size_t cbData) const override
    {
        // ������� �������� ������
        VARIANT varString = Decoder().GetValue(pvData, cbData); 
        try {
            // ������������� ������
            VARIANT varValue = DecodeString(V_BSTR(&varString));  

            // ���������� ���������� �������
            ::VariantClear(&varString); return varValue; 
        }
        // ��� ������ ���������� ���������� �������
        catch (...) { ::VariantClear(&varString); throw; }
    }
    // ������ ������������� �����
    protected: virtual const BasicType& Decoder() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ��� ������
///////////////////////////////////////////////////////////////////////////////
class BinaryType : public BasicType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_BINARY; } 

    // �OM-��� ��������
    public: virtual VARTYPE VariantType() const override { return VT_UI1 | VT_ARRAY; }
    // ���������� c COM-��������������
    public: virtual BOOL IsVariantLayout() const override { return FALSE; }

    // �������� ������ ��������
    public: virtual size_t GetSize(const IContainer&, const void*, size_t) const override; 
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void*, size_t) const override; 

    // ���������� ������ ������
    protected: virtual size_t GetSize(const ETW::IContainer&) const { return SIZE_MAX; } 

    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ���� ������
///////////////////////////////////////////////////////////////////////////////
class GuidType : public BinaryType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_BINARY_GUID; }

    // ���������� ��� ������
    public: virtual USHORT InputType () const override { return TDH_INTYPE_GUID; }
    // ������ ��������������
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_GUID; }

    // �������� ������ ��������
    public: virtual size_t GetSize(const IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(GUID)) ThrowBadData(); return sizeof(GUID); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};

class SidType : public BinaryType
{
    // �����������
    public: SidType(size_t pointerSize) : _pointerSize(pointerSize) {} private: size_t _pointerSize;

    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_BINARY_SID; }
    // ������ ��������������
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_STRING; }

    // �������� ������ ��������
    public: virtual size_t GetSize(const IContainer&, const void*, size_t) const override; 
    // �������� �������� ��������
    public: virtual VARIANT GetValue(const void*, size_t) const override; 

    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};

class IPv4Type : public UInt32Type
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_UINT32_IPV4; }
    // ������ ��������������
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_IPV4; }

    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT&, std::wostringstream&) const override; 
};

class IPv6Type : public BinaryType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_BINARY_IPV6; }
    // ������ ��������������
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_IPV6; }

    // ���������� ��� ������
    public: virtual USHORT InputType () const override { return TDH_INTYPE_BINARY; }
    // �������� ������ ��������
    public: virtual size_t GetSize(const IContainer&, const void*, size_t cbRemaining) const override
    {
        // ��������� ������� ������
        if (cbRemaining < sizeof(IN6_ADDR)) ThrowBadData(); return sizeof(IN6_ADDR); 
    }
    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};

class SocketAddressType : public BinaryType
{
    // ���������� ��� ��������
    public: virtual ULONG LogicalType() const override { return TYPE_BINARY_SOCKETADDRESS; }
    // ������ ��������������
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_SOCKETADDRESS; }

    // ���������� ��� ������
    public: virtual USHORT InputType () const override { return TDH_INTYPE_BINARY; }

    // �������� ��������� �������������
    protected: virtual void Format(const VARIANT& value, std::wostringstream& stream) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ����
///////////////////////////////////////////////////////////////////////////////
class BasicElement : public IBasicElement
{
    // ���� �������� � ��� ���
    private: const IContainer& _parent; std::wstring _path; const IBasicType& _type; 
    // ����� � ������ ������ 
    private: const void* _pvData; size_t _cbData; 

    // �����������
    public: BasicElement(const IContainer& parent, const std::wstring& path, 
        const IBasicType& type, const void* pvData, size_t cbData)

        // ��������� ���������� ���������
        : _parent(parent), _path(path), _type(type), _pvData(pvData) 
    {
        // ���������� ������ ������
        _cbData = type.GetSize(parent, pvData, cbData); 
    }
    // ���� � ��������
    public: virtual PCWSTR Path() const override { return _path.c_str(); } 
    // ��� ��������
    public: virtual const IElementType& Type() const override { return _type; }

    // ����� � ������ ������
    public: virtual const void* GetDataAddress() const override { return _pvData; }
    public: virtual size_t      GetDataSize   () const override { return _cbData; }

    // ��������� �������������
    public: virtual BSTR ToString() const override
    { 
        // �������� ��������� �������������
        return _type.ToString(_parent, _pvData, _cbData); 
    }
}; 
///////////////////////////////////////////////////////////////////////////////
// ������
///////////////////////////////////////////////////////////////////////////////
class Array : public IContainer
{
    // ���� �������� � ��� ���
    private: std::wstring _path; const IArrayType& _type; 
    // �����, ������ ������ � COM-������
    private: const void* _pvData; size_t _cbData; SAFEARRAY* _pSafeArray;

    // �����������
    public: Array(const IContainer&, const std::wstring&, const IArrayType&, const void*, size_t); 
    // ����������
    public: virtual ~Array() { ::SafeArrayDestroy(_pSafeArray); }

    // ���� � ��������
    public: virtual PCWSTR Path() const override { return _path.c_str(); } 
    // ��� ��������
    public: virtual const IElementType& Type() const override { return _type; }

    // ����� � ������ ������
    public: virtual const void* GetDataAddress() const override { return _pvData; }
    public: virtual size_t      GetDataSize   () const override { return _cbData; }

    // �������� ��������
    public: virtual VARIANT GetValue() const override
    {
        // ������� ��� �������
        VARIANT varValue; ::VariantInit(&varValue); V_VT(&varValue) = Type().VariantType(); 

        // ����������� �������� �������
        HRESULT hr = ::SafeArrayCopy(_pSafeArray, &V_ARRAY(&varValue)); 
        
        // ��������� ���������� ������
        if (FAILED(hr)) Exception::Throw(hr); return varValue; 
    }
    // ����� ���������
    public: virtual size_t Count() const override { return _items.size(); }
    // �������� �������� ����������� ��������
    public: virtual const IElement& operator[](size_t i) const override { return *_items[i]; }
    // ������� ���������
    private: std::vector<std::shared_ptr<IElement> > _items; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���� ���������
///////////////////////////////////////////////////////////////////////////////
class Field : public IField
{
    // ��� � ��� ���� ���������
    private: std::wstring _name; std::shared_ptr<IElementType> _pType; 

    // �����������
    public: Field(const std::wstring& name, const std::shared_ptr<IElementType>& pType)

        // ��������� ���������� ���������
        : _name(name), _pType(pType) {} 

    // ��� ���� ���������
    public: virtual PCWSTR Name() const override { return _name.c_str(); } 
    // ��� ���� ���������
    public: virtual const IElementType& Type() const override { return *_pType; }
};

///////////////////////////////////////////////////////////////////////////////
// COM-�������� ���������
///////////////////////////////////////////////////////////////////////////////
class RecordInfo : public IRecordInfo
{
    // �������� �����, ������ ��������� � ������� ������
    private: const IStructType& _structType; ULONG _cb; ULONG _cRef;

    // �����������
    public: RecordInfo(const IStructType& structType); 
    // ����������
    protected: virtual ~RecordInfo() {}

    // ��������� ���������
    public: STDMETHOD(QueryInterface)(REFIID riid, void** ppv) override; 

    // ��������� ������� ������
    public: STDMETHOD_(ULONG, AddRef)() override 
    { 
        // ��������� ������� ������
        return ::InterlockedIncrement(&_cRef); 
    }
    // ��������� ������� ������
    public: STDMETHOD_(ULONG, Release)() override 
    { 
        // ��������� ������� ������
        ULONG cRef = ::InterlockedDecrement(&_cRef); 

        // ��� ������������� ������� ������
        if (cRef == 0) delete this; return cRef; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // �������������� ������
    ///////////////////////////////////////////////////////////////////////////

    // GUID ���� ���������
    public: STDMETHOD(GetGuid)(GUID* pguid) override
    {
        // ����������� GUID ���� ���������
        if (!pguid) return E_POINTER; *pguid = _structType.Guid(); return S_OK; 
    }
    // ��� ���������
    public: STDMETHOD(GetName)(BSTR* pbstrName) override
    {
        // ��������� ������� ���������
        if (!pbstrName) return E_POINTER; PCWSTR szName = _structType.Name(); 

        // ��������� ������� �����
        if (!szName) { *pbstrName = nullptr; return S_OK; }

        // ����������� ��� ���������
        *pbstrName = ::SysAllocString(szName); 

        // ��������� ���������� ������
        return (*pbstrName) ? S_OK : E_OUTOFMEMORY; 
    }
    // ��������� ���������� ��������
    public: STDMETHOD_(BOOL, IsMatchingType)(IRecordInfo* pRecordInfo) override; 

    // �������� ��������� ITypeInfo
    public: STDMETHOD(GetTypeInfo)(ITypeInfo**) override
    {
        // �������� �� ��������������
        return TYPE_E_INVALIDSTATE; 
    }
    // �������� ������ ����������
    public: STDMETHOD(GetSize)(ULONG* pcbSize) override
    {
        // ������� ������ ����������
        if (!pcbSize) return E_POINTER; *pcbSize = _cb; return S_OK;
    }
    // ����������� ����� �����
    public: STDMETHOD(GetFieldNames)(ULONG* pcNames, BSTR* rgBstrNames) override; 

    ///////////////////////////////////////////////////////////////////////////
    // ��������, �������� � ����������� ���������
    ///////////////////////////////////////////////////////////////////////////

    // �������� ������ ��� ���������
    public: STDMETHOD_(PVOID, RecordCreate)() override
    {
        // �������� ������ ��� ���������
        return ::CoTaskMemAlloc(_cb); 
    }
    // ���������� ������ ���������
    public: STDMETHOD(RecordDestroy)(PVOID pvRecord) override
    {
        // ���������� ������ ���������
        ::CoTaskMemFree(pvRecord); return S_OK; 
    }
    // �������� ������ � ����������� ���������
    public: STDMETHOD(RecordCreateCopy)(PVOID pvSource, PVOID* ppvDest) override; 

    // ���������������� ���������
    public: STDMETHOD(RecordInit)(PVOID pvNew) override
    {
        // ���������������� ���������
        memset(pvNew, 0, _cb); return S_OK; 
    }
    // ���������� ������������ �������
    public: STDMETHOD(RecordClear)(PVOID pvExisting) override; 

    // ����������� ���������
    public: STDMETHOD(RecordCopy)(PVOID pvExisting, PVOID pvNew) override; 

    ///////////////////////////////////////////////////////////////////////////
    // ���������� ����� ���������
    ///////////////////////////////////////////////////////////////////////////
       
    // �������� ������ �� �������� ����
    public: STDMETHOD(GetFieldNoCopy)(PVOID pvData, 
        LPCOLESTR szFieldName, VARIANT* pvarField, PVOID* ppvDataCArray) override; 

    // �������� �������� ���� 
    public: STDMETHOD(GetField)(PVOID pvData, 
        LPCOLESTR szFieldName, VARIANT* pvarField) override
    {
        // ��������� ������� ���������
        if (!pvarField) return E_POINTER; VARIANT var; ::VariantInit(&var); 
    
        // �������� ������ �� �������� ����
        HRESULT hr = GetFieldNoCopy(pvData, szFieldName, &var, nullptr); 

        // ��������� ����������� �������� � ��������������
        return (SUCCEEDED(hr)) ? ::VariantCopyInd(&var, pvarField) : hr; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // ��������� ����� ���������
    ///////////////////////////////////////////////////////////////////////////
     
    // ���������� �������� ���� � ��������� ��������
    public: STDMETHOD(PutFieldNoCopy)(ULONG wFlags, 
        PVOID pvData, LPCOLESTR szFieldName, VARIANT* pvarField) override; 

    // ���������� �������� ���� 
    public: STDMETHOD(PutField)(ULONG wFlags, 
        PVOID pvData, LPCOLESTR szFieldName, VARIANT* pvarField) override
    {
        // ��������� ������� ���������
        if (!pvarField) return E_POINTER; VARIANT var; ::VariantInit(&var); 

        // ����������� �������� � ������������ ��������
        HRESULT hr = ::VariantCopy(&var, pvarField); if (FAILED(hr)) return hr; 

        // ���������� �������� ���� � ��������� ��������
        hr = PutFieldNoCopy(wFlags, pvData, szFieldName, pvarField); 

        // ��������� ���������� ������
        if (FAILED(hr)) ::VariantClear(&var); return hr; 
    }
    ///////////////////////////////////////////////////////////////////////////
    // ����������� �������� � ��������
    ///////////////////////////////////////////////////////////////////////////
    private: const IElementType* FindFieldType(LPCOLESTR szFieldName) const
    {
        // ������� ��� �������
        typedef std::map<std::wstring, size_t> map_type; 

        // ����� ������� �� �����
        typename map_type::const_iterator p = _indexes.find(szFieldName); 
        
        // ������� ��������� �������
        return (p != _indexes.end()) ? &_structType.GetField(p->second).Type() : nullptr; 
    }
    private: const size_t FindFieldOffset(LPCOLESTR szFieldName) const
    {
        // ������� ��� �������
        typedef std::map<std::wstring, size_t> map_type; 

        // ����� ������� �� �����
        typename map_type::const_iterator p = _offsets.find(szFieldName); 
        
        // ������� ��������� �������
        return (p != _offsets.end()) ? p->second : SIZE_MAX; 
    }
    // ������ �������� �����
    private: std::map<std::wstring, size_t> _indexes; 
    // ������ �������� �����
    private: std::map<std::wstring, size_t> _offsets; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���������
///////////////////////////////////////////////////////////////////////////////
class Struct : public IStruct
{
    // ���� �������� � ��� ���
    private: std::wstring _path; const IStructType& _type;
    // ����� � ������ ������ 
    private: const void* _pvData; size_t _cbData; void* _pvRecord;

    // �����������
    public: Struct(const std::wstring&, const IStructType&, const void*, size_t); 
    // ����������
    public: virtual ~Struct() 
    { 
        // ���������� ���������� �������
        if (_pvRecord != _pvData) ::CoTaskMemFree(_pvRecord); 
    }
    // ���� � ��������
    public: virtual PCWSTR Path() const override { return _path.c_str(); } 
    // ��� ��������
    public: virtual const IElementType& Type() const override { return _type; }

    // ����� � ������ ������
    public: virtual const void* GetDataAddress() const override { return _pvData; }
    public: virtual size_t      GetDataSize   () const override { return _cbData; }

    // �������� ��������
    public: virtual VARIANT GetValue() const override; 

    // ����� ���������
    public: virtual size_t Count() const override { return _items.size(); }

    // �������� ���������� �������
    public: virtual const IElement& operator[](size_t i) const override 
    { 
        // �������� ���������� �������
        return *_items.at(_names[i]); 
    }
    // ����� ������� �� ����
    public: virtual const ETW::IElement* FindPath(PCWSTR szPath) const override; 
    // ����� ������� �� �����
    public: virtual const IElement* FindName(PCWSTR szName) const override
    {
        // ����� ������� �� �����
        map_type::const_iterator p = _items.find(szName); 
        
        // ������� ��������� �������
        return (p != _items.end()) ? p->second.get() : nullptr; 
    }
    // ��� ������� ���������
    private: typedef std::map<std::wstring, std::shared_ptr<IElement> > map_type; 
    // ������� ���� � ���������
    private: std::vector<std::wstring> _names; map_type _items;
}; 

}
