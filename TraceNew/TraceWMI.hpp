#pragma once
#include "TraceWMI.h"
#include "TraceETW.hpp"
#include <comdef.h>

///////////////////////////////////////////////////////////////////////////////
// ����������� �����������
///////////////////////////////////////////////////////////////////////////////
_COM_SMARTPTR_TYPEDEF(IWbemServices    , __uuidof(IWbemServices    ));
_COM_SMARTPTR_TYPEDEF(IWbemClassObject , __uuidof(IWbemClassObject ));
_COM_SMARTPTR_TYPEDEF(IWbemQualifierSet, __uuidof(IWbemQualifierSet));

namespace WMI {

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ��� ����
///////////////////////////////////////////////////////////////////////////////
class ValueInfo : public ETW::IValueInfo
{ 
    // ��������, ��� ��� � ���������
    private: ULONGLONG _value; _bstr_t _bstrName; _bstr_t _bstrDescription; 

    // �����������
    public: ValueInfo(ULONGLONG value, BSTR bstrName, BSTR bstrDescription) 
        
        // ��������� ���������� ���������
        : _value(value), _bstrName(bstrName), _bstrDescription(bstrDescription) {}

    // ��������
    public: virtual ULONGLONG Value() const override { return _value; } 
    // ��� ��������
    public: virtual PCWSTR Name() const override { return _bstrName; } 

    // �������� ��������
    public: virtual PCWSTR Description() const override { return _bstrDescription; } 
};

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ��� �����
///////////////////////////////////////////////////////////////////////////////
class ValueMap : public ETW::IValueMap
{ 
    // ��� �������� � ������� �������� �����
    private: ETW::ValueMapType _valueType; std::vector<ValueInfo> _map;

    // �����������
    public: ValueMap(IWbemQualifierSet* pQualifiers, BOOL forceFlags = FALSE); 
    // �����������
    public: ValueMap() : _valueType(ETW::ValueMapType::Index) {}

    // ��� ��������
    public: virtual ETW::ValueMapType Type() const override { return _valueType; }

    // ����� ��������
    public: virtual size_t Count() const override { return _map.size(); } 
    // �������� �������� ��� �����
    public: virtual const ETW::IValueInfo& Item(size_t i) const override { return _map[i]; } 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ���
///////////////////////////////////////////////////////////////////////////////
class BooleanType : public ETW::BooleanType, public IBasicType 
{
    // �������� �������� � �������� ��������
    private: IWbemQualifierSetPtr _pQualifiers; ValueMap _valueMap; 

    // �����������
    public: BooleanType(IWbemQualifierSet* pQualifiers) : _pQualifiers(pQualifiers), _valueMap(pQualifiers) {}

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return CIM_BOOLEAN; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return TDH_INTYPE_BOOLEAN;  }
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_BOOLEAN; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // �������� �������� �������� ��� �����
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// ���� �����
///////////////////////////////////////////////////////////////////////////////
class Int8Type : public ETW::Int8Type, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // ������ �������������� � �������� ��������
    private: USHORT _outType; ValueMap _valueMap;

    // �����������
    public: Int8Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ������ ��������������
    public: virtual USHORT OutputType() const override { return _outType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // �������� �������� �������� ��� �����
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class UInt8Type : public ETW::UInt8Type, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // ������ �������������� � �������� ��������
    private: USHORT _outType; ValueMap _valueMap;

    // �����������
    public: UInt8Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ������ ��������������
    public: virtual USHORT OutputType() const override { return _outType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // �������� �������� �������� ��� �����
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class Int16Type : public ETW::Int16Type, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // ������ �������������� � �������� ��������
    private: USHORT _outType; ValueMap _valueMap;

    // �����������
    public: Int16Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ������ ��������������
    public: virtual USHORT OutputType() const override { return _outType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // �������� �������� �������� ��� �����
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class UInt16Type : public ETW::UInt16Type, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // ������ �������������� � �������� ��������
    private: USHORT _outType; ValueMap _valueMap;

    // �����������
    public: UInt16Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT OutputType() const override { return _outType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // �������� �������� �������� ��� �����
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class Int32Type : public ETW::Int32Type, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // ������ �������������� � �������� ��������
    private: USHORT _outType; ValueMap _valueMap;

    // �����������
    public: Int32Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ������ ��������������
    public: virtual USHORT OutputType() const override { return _outType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // �������� �������� �������� ��� �����
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class UInt32Type : public ETW::UInt32Type, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // ������ �������������� � �������� ��������
    private: USHORT _outType; ValueMap _valueMap;

    // �����������
    public: UInt32Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ������ ��������������
    public: virtual USHORT OutputType() const override { return _outType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // �������� �������� �������� ��� �����
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class Int64Type : public ETW::Int64Type, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // ������ �������������� � �������� ��������
    private: USHORT _outType; ValueMap _valueMap;

    // �����������
    public: Int64Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT OutputType() const override { return _outType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // �������� �������� �������� ��� �����
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class UInt64Type : public ETW::UInt64Type, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // ������ �������������� � �������� ��������
    private: USHORT _outType; ValueMap _valueMap;

    // �����������
    public: UInt64Type(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ������ ��������������
    public: virtual USHORT OutputType() const override { return _outType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // �������� �������� �������� ��� �����
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};
class FloatType : public ETW::FloatType, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // �����������
    public: FloatType(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // ��������� ���������� ���������
        : _type(type), _pQualifiers(pQualifiers) {}

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }
};
class DoubleType : public ETW::DoubleType, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // �����������
    public: DoubleType(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // ��������� ���������� ���������
        : _type(type), _pQualifiers(pQualifiers) {}

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }
};

///////////////////////////////////////////////////////////////////////////////
// ��� ��������� ��� ����� ����������� ���������
///////////////////////////////////////////////////////////////////////////////
class PointerType : public ETW::PointerType, public IBasicType 
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers; ValueMap _valueMap; 
    // ���������� � ���������� ���� ��������
    private: USHORT _inType; USHORT _outType; size_t _pointerSize; 

    // �����������
    public: PointerType(CIMTYPE type, IWbemQualifierSet* pQualifiers, size_t pointerSize); 

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _inType;  }
    public: virtual USHORT OutputType() const override { return _outType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override 
    { 
        // �������� �������� �������� ��� �����
        return (_valueMap.Count() > 0) ? &_valueMap : nullptr; 
    }
};

///////////////////////////////////////////////////////////////////////////////
// ��� �����
///////////////////////////////////////////////////////////////////////////////
class StringType : public ETW::StringType, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // ���������� � ���������� ���� ��������
    private: USHORT _inType; USHORT _outType; 

    // �����������
    public: StringType(CIMTYPE type, IWbemQualifierSet* pQualifiers); 

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _inType;  }
    public: virtual USHORT OutputType() const override { return _outType; }

    // �������� ������ ��������
    public: virtual size_t GetSize(const ETW::IContainer&, const void*, size_t) const override; 

    // ���������� ������ ������
    protected: virtual size_t GetLength(const ETW::IContainer*) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ��� �������
///////////////////////////////////////////////////////////////////////////////
class DateTimeType : public ETW::DateTimeType, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers; 

    // �����������
    public: DateTimeType(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // ��������� ���������� ���������
        : _type(type), _pQualifiers(pQualifiers) {}

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return TDH_INTYPE_FILETIME;  }
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_DATETIME; }
};
 
class CimDateTimeType : public ETW::CimDateTimeType, public IBasicType
{
    // ���, �������� �������� � ������ ������������� �����
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers; StringType _decoder;

    // �����������
    public: CimDateTimeType(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // ��������� ���������� ���������
        : _type(type), _pQualifiers(pQualifiers), _decoder(type, pQualifiers) {}
        
    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ���������� ��� ������
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_CIMDATETIME; }

    // ������ ������������� �����
    protected: virtual const BasicType& Decoder() const override { return _decoder; } 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ��� ������
///////////////////////////////////////////////////////////////////////////////
class BinaryType : public ETW::BinaryType, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // �����������
    public: BinaryType(CIMTYPE type, IWbemQualifierSet* pQualifiers) 

        // ��������� ���������� ���������
        : _type(type), _pQualifiers(pQualifiers) {}
        
    // ��� ������
    public: virtual CIMTYPE CimType() const override { return CIM_OBJECT; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return TDH_INTYPE_HEXDUMP;    }
    public: virtual USHORT OutputType() const override { return TDH_OUTTYPE_HEXBINARY; }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ���� ������
///////////////////////////////////////////////////////////////////////////////
class GuidType : public ETW::GuidType, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // �����������
    public: GuidType(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // ��������� ���������� ���������
        : _type(type), _pQualifiers(pQualifiers) {}

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }
};

class SidType : public ETW::SidType, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // �����������
    public: SidType(CIMTYPE type, IWbemQualifierSet* pQualifiers, size_t pointerSize)

        // ��������� ���������� ���������
        : ETW::SidType(pointerSize), _type(type), _pQualifiers(pQualifiers) {}

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }

    // ���������� ��� ������
    public: virtual USHORT InputType () const override { return TDH_INTYPE_WBEMSID; }
};

class IPv4Type : public ETW::IPv4Type, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // �����������
    public: IPv4Type(CIMTYPE type, IWbemQualifierSet* pQualifiers) 

        // ��������� ���������� ���������
        : _type(type), _pQualifiers(pQualifiers) {}

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }
};

class IPv6Type : public ETW::IPv6Type, public IBasicType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;

    // �����������
    public: IPv6Type(CIMTYPE type, IWbemQualifierSet* pQualifiers)

        // ��������� ���������� ���������
        : _type(type), _pQualifiers(pQualifiers) {}

    // ��� ������
    public: virtual CIMTYPE CimType() const override { return _type; }
    // �������� ����
    public: virtual IWbemQualifierSet* Qualifiers() const override { return _pQualifiers; }
};
 
///////////////////////////////////////////////////////////////////////////////
// ��� �������
///////////////////////////////////////////////////////////////////////////////
class ArrayType : public ETW::IArrayType
{
    // ��� � �������� ��������
    private: CIMTYPE _type; IWbemQualifierSetPtr _pQualifiers;
    // ��� ��������� �������
    private: std::shared_ptr<ETW::IElementType> _pElementType; 

    // �����������
    public: ArrayType(const class Event&, CIMTYPE, IWbemQualifierSet*); 

    // �������� ���� ��������
    public: virtual const ETW::IElementType& ElementType() const override 
    { 
        return *_pElementType; 
    } 
    // ���������� ������ �������
    public: virtual size_t GetCount(const ETW::IContainer& parent) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��� ���������
///////////////////////////////////////////////////////////////////////////////
class StructType : public ETW::IStructType
{
    // ������������� � ������ ���������
    private: GUID _id; IWbemClassObjectPtr _pClass; 
    // �������������, ��� ������ � ������� �����
    private: std::wstring _name; std::vector<ETW::Field> _fields; 

    // �����������
    public: StructType(const class Event&, IWbemClassObject*, PCWSTR); 

    // GUID ���������
    public: virtual REFGUID Guid() const override { return _id; }
    // ��� ���������
    public: virtual PCWSTR Name() const override { return _name.c_str(); }

    // ����� �����
    public: virtual size_t FieldCount() const override { return _fields.size(); }   
    // �������� ���� �� �������
    public: virtual const ETW::IField& GetField(size_t i) const override { return _fields[i]; }
}; 

///////////////////////////////////////////////////////////////////////////////
// C������ � ��������� � ��� ����������
///////////////////////////////////////////////////////////////////////////////
class Event : public ETW::IEvent
{
    // ������������ ���� � ������ ���������
    private: IWbemServicesPtr _pNamespace; size_t _pointerSize; 
    // ������ ������� � ������ ���������
    private: const EVENT_TRACE* _pEvent; IWbemClassObjectPtr _pClass; 

    // ��� ���������
    private: std::unique_ptr<ETW::IStructType> _pStructType; 
    // ��������������� ���������
    private: std::unique_ptr<ETW::IStruct> _pStruct; 

    // �����������
    public: Event(IWbemServices*, IWbemClassObject*, const EVENT_TRACE*, size_t); 

    // ����� � ������ ������
    public: virtual const void* GetDataAddress() const override { return _pEvent->MofData;   }
    public: virtual size_t      GetDataSize   () const override { return _pEvent->MofLength; }

    // ��������������� ���������
    public: virtual const ETW::IStruct& Struct() const override { return *_pStruct; }

    // ������ ���������
    public: virtual size_t PointerSize() const override { return _pointerSize; }

    // ������� ��� ��������
    public: ETW::IElementType* CreateElementType(CIMTYPE type, IWbemQualifierSet* pQualifiers) const; 
};  

///////////////////////////////////////////////////////////////////////////////
// �������� ����������
///////////////////////////////////////////////////////////////////////////////
class ProviderInfo : public ETW::IProviderInfo
{
    // ������ ������������ ���� � GUID ����������
    private: IWbemServicesPtr _pNamespace; GUID _id; 
    // ������ ������ ����������
    private: IWbemClassObjectPtr _pProvider; 

    // �������� ��������� � �������
    private: std::unique_ptr<ValueMap> _pKeywords; 
    private: std::unique_ptr<ValueMap> _pLevels;

    // �����������
    public: ProviderInfo(IWbemServices*, const GUID&, IWbemClassObject*); 
        
    // ������������� ����������
    public: virtual const GUID& ID() const { return _id; }

    // �������� �������� ��������� �����������
    public: virtual const ETW::IValueMap& Keywords() const override { return *_pKeywords; } 
    // �������� �������� ������� �����������
    public: virtual const ETW::IValueMap& Levels() const override { return *_pLevels; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������������ ���� WMI
///////////////////////////////////////////////////////////////////////////////
class Namespace : public INamespace
{
    // �����������
    public: Namespace(IWbemServices* pNamespace) : _pNamespace(pNamespace) {}
    // �����������
    public: Namespace(); private: IWbemServicesPtr _pNamespace;

    // ����� ��������� �������
    public: virtual std::unique_ptr<ETW::IProviderInfo> FindEventProvider(REFGUID guid) const override
    {
        // ����� ����� ���������� ������� 
        IWbemClassObjectPtr pProviderClass = FindEventProviderClass(guid); 

        // ��������� ������� ����������
        if (!pProviderClass) return std::unique_ptr<ETW::IProviderInfo>(); 

        // ������� ��������� �������
        return std::unique_ptr<ETW::IProviderInfo>(new ProviderInfo(_pNamespace, guid, pProviderClass)); 
    }
    // ������������� �������
    public: virtual std::unique_ptr<ETW::IEvent> DecodeEvent(PEVENT_TRACE pEvent, size_t pointerSize) const override
    {
        // ������� �� ��������� �������
        const EVENT_TRACE_HEADER& header = pEvent->Header; 

        // �������� ������������� �������
        REFGUID guid = (header.Flags & WNODE_FLAG_USE_GUID_PTR) ? *(GUID*)header.GuidPtr : header.Guid; 

        // ����� ����� ������� 
        IWbemClassObjectPtr pEventClass = FindEventClass(guid, header.Class.Version, header.Class.Type); 

        // ��������� ������� �������
        if (!pEventClass) ETW::Exception::Throw(WBEM_E_NOT_FOUND); 

        // ������������� �������
        return std::unique_ptr<ETW::IEvent>(new Event(_pNamespace, pEventClass, pEvent, pointerSize)); 
    }
    // ����� ����� ���������� ������� 
    private: IWbemClassObjectPtr FindEventProviderClass(REFGUID) const; 
    // ����� ����� ��������� �������
    private: IWbemClassObjectPtr FindEventCategoryClass(REFGUID, USHORT) const; 
    // ����� ����� �������
    private: IWbemClassObjectPtr FindEventClass(REFGUID, USHORT, UCHAR) const; 
};
}
