#pragma once
#include <evntrace.h>

namespace ETW {

///////////////////////////////////////////////////////////////////////////////
// ������������� SAFEARRAY ��� ������������� ����
///////////////////////////////////////////////////////////////////////////////
template <typename T>
class VariantArrayCast
{
    // ������ �� ���������� ���
    private: const VARIANT& _var; const T* _ptr; 

    // �����������
    public: VariantArrayCast(const VARIANT& var) : _var(var), _ptr(nullptr)
    {
        // �������� ������ � ������
        ::SafeArrayAccessData(V_ARRAY(&_var), (void**)&_ptr); 
    }
    // ����������
    public: ~VariantArrayCast() 
    {
        // ���������� �� ������� � ������
        if (_ptr) ::SafeArrayUnaccessData(V_ARRAY(&_var)); 
    } 
    // �������� �������������� ����
    public: operator const T*() const { return _ptr; }
};

///////////////////////////////////////////////////////////////////////////////
// �������������� ���� ������
///////////////////////////////////////////////////////////////////////////////
const ULONG TYPE_NULL                     =  0 | (0 << 4) | (0 << 7); 
const ULONG TYPE_ARRAY                    =  0 | (0 << 4) | (1 << 7); 
const ULONG TYPE_STRUCT                   =  0 | (0 << 4) | (2 << 7); 
const ULONG TYPE_BOOLEAN                  =  1 | (0 << 4) | (0 << 7); 
const ULONG TYPE_INT8                     =  2 | (0 << 4) | (0 << 7); 
const ULONG TYPE_UINT8                    =  3 | (0 << 4) | (0 << 7); 
const ULONG TYPE_INT16                    =  4 | (0 << 4) | (0 << 7); 
const ULONG TYPE_UINT16                   =  5 | (0 << 4) | (0 << 7); 
const ULONG TYPE_INT32                    =  6 | (0 << 4) | (0 << 7); 
const ULONG TYPE_UINT32                   =  7 | (0 << 4) | (0 << 7); 
const ULONG TYPE_UINT32_IPV4              =  7 | (1 << 4) | (0 << 7); 
const ULONG TYPE_INT64                    =  8 | (0 << 4) | (0 << 7); 
const ULONG TYPE_UINT64                   =  9 | (0 << 4) | (0 << 7); 
const ULONG TYPE_SIZE_T                   = 10 | (0 << 4) | (0 << 7); 
const ULONG TYPE_POINTER                  = 10 | (1 << 4) | (0 << 7); 
const ULONG TYPE_FLOAT                    = 11 | (0 << 4) | (0 << 7); 
const ULONG TYPE_DOUBLE                   = 12 | (0 << 4) | (0 << 7); 
const ULONG TYPE_DATE                     = 13 | (0 << 4) | (0 << 7); 
const ULONG TYPE_STRING                   = 14 | (0 << 4) | (0 << 7); 
const ULONG TYPE_BINARY                   = 15 | (0 << 4) | (0 << 7); 
const ULONG TYPE_BINARY_GUID              = 15 | (1 << 4) | (0 << 7); 
const ULONG TYPE_BINARY_SID               = 15 | (2 << 4) | (0 << 7); 
const ULONG TYPE_BINARY_IPV6              = 15 | (3 << 4) | (0 << 7); 
const ULONG TYPE_BINARY_SOCKETADDRESS     = 15 | (4 << 4) | (0 << 7); 

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ��� ����
///////////////////////////////////////////////////////////////////////////////
enum class ValueMapType { Index, Flag };

struct IValueInfo { virtual ~IValueInfo() {}

    // ��������
    virtual ULONGLONG Value() const = 0; 
    // ��� ��������
    virtual PCWSTR Name() const = 0; 

    // �������� ��������
    virtual PCWSTR Description() const { return nullptr; }
};

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ��� �����
///////////////////////////////////////////////////////////////////////////////
struct IValueMap { virtual ~IValueMap() {}

    // ��� ��������
    virtual ValueMapType Type() const = 0; 
    // ����� ��������
    virtual size_t Count() const = 0; 

    // �������� �������� ��� �����
    virtual const IValueInfo& Item(size_t) const = 0; 

    // ��������� ������������� ��������
    virtual BSTR ToString(ULONGLONG value) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ��� �������� ������
///////////////////////////////////////////////////////////////////////////////
struct IElementType { virtual ~IElementType() {}

    // ���������� ��� ��������
    virtual ULONG LogicalType() const = 0; 

    // COM-��� ��������
    virtual VARTYPE VariantType() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������
///////////////////////////////////////////////////////////////////////////////
struct IElement { virtual ~IElement() {}

    // ���� � ��������
    virtual PCWSTR Path() const = 0; 

    // ����� ������
    virtual const void* GetDataAddress() const = 0; 
    // ������ ������
    virtual size_t GetDataSize() const = 0; 

    // ��� ��������
    virtual const IElementType& Type() const = 0; 
    // �������� ��������
    virtual VARIANT GetValue() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ����
///////////////////////////////////////////////////////////////////////////////
struct IBasicType : IElementType
{
    // �������� �������� ��� �����
    virtual const IValueMap* GetValueMap() const { return nullptr; } 

    // �������� ������ ��������
    virtual size_t GetSize(const struct IContainer&, const void*, size_t) const = 0; 

    // �������� �������� ��������
    virtual VARIANT GetValue(const void* pvData, size_t cbData) const = 0; 

    // �������� ��������� �������������
    virtual BSTR ToString(const struct IContainer&, const void*, size_t) const { return nullptr; } 
};

struct IBasicElement : IElement
{
    // �������� ��������
    virtual VARIANT GetValue() const override
    {
        // ��������� �������������� ����
        const IBasicType& type = (const IBasicType&)Type(); 

        // �������� �������� ��������
        return type.GetValue(GetDataAddress(), GetDataSize()); 
    }
    // ��������� �������������
    virtual BSTR ToString() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� � ��������� ����������
///////////////////////////////////////////////////////////////////////////////
struct IContainer : IElement
{ 
    // ����� ���������
    virtual size_t Count() const = 0; 

    // �������� ���������� �������
    virtual const IElement& operator[](size_t i) const = 0;
};

///////////////////////////////////////////////////////////////////////////////
// ������
///////////////////////////////////////////////////////////////////////////////
struct IArrayType : IElementType
{
    // ���������� ��� ��������
    virtual ULONG LogicalType() const override { return TYPE_ARRAY; }

    // COM-��� ��������
    virtual VARTYPE VariantType() const override 
    { 
        // �������� ��� ��������� ��������
        VARTYPE childType = ElementType().VariantType(); 

        // ��������� ������� ����������� �������
        return (childType & VT_ARRAY) ? VT_ARRAY : (VT_ARRAY | childType); 
    }
    // ������� ��� ���������
    virtual const IElementType& ElementType() const = 0; 

    // �������� ������ �������
    virtual size_t GetCount(const struct IContainer&) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���� ���������
///////////////////////////////////////////////////////////////////////////////
struct IField
{
    // ��� ���� ���������
    virtual PCWSTR Name() const = 0; 
    // ��� ���� ���������
    virtual const IElementType& Type() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ���������
///////////////////////////////////////////////////////////////////////////////
struct IStructType : IElementType
{
    // ���������� ��� ��������
    virtual ULONG LogicalType() const override { return TYPE_STRUCT; }
    // COM-��� ��������
    virtual VARTYPE VariantType() const override { return VT_RECORD; }

    // GUID ���������
    virtual REFGUID Guid() const = 0; 
    // ��� ���������
    virtual PCWSTR Name() const { return nullptr; }

    // ����� �����
    virtual size_t FieldCount() const = 0;
    // �������� ���� �� �������
    virtual const IField& GetField(size_t i) const = 0;
}; 

struct IStruct : IContainer
{
    // ����� ������� �� �����
    virtual const IElement* FindName(PCWSTR szName) const = 0;  
    // ����� ������� �� ����
    virtual const IElement* FindPath(PCWSTR szPath) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// C������
///////////////////////////////////////////////////////////////////////////////
struct IEvent { virtual ~IEvent() {}

    // ����� � ������ ������
    virtual const void* GetDataAddress() const = 0; 
    virtual size_t      GetDataSize   () const = 0; 

    // ��������������� ���������
    virtual const IStruct& Struct() const = 0; 

    // ������ ���������
    virtual size_t PointerSize() const = 0; 
};  

///////////////////////////////////////////////////////////////////////////////
// �������� ����������
///////////////////////////////////////////////////////////////////////////////
struct IProviderInfo { virtual ~IProviderInfo() {}

    // ������������� ����������
    virtual const GUID& ID() const = 0; 

    // �������� �������� ��������� �����������
    virtual const IValueMap& Keywords() const = 0; 
    // �������� �������� ������� �����������
    virtual const IValueMap& Levels() const = 0; 
}; 

}
