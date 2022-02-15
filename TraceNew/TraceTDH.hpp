#pragma once
#include "TraceETW.hpp"

namespace TDH {

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ��� ����
///////////////////////////////////////////////////////////////////////////////
class EventValueInfo : public ETW::IValueInfo
{ 
    // �������� �������� � ������ ��������
    private: const EVENT_MAP_INFO* _pInfo; size_t _index; 

    // �����������
    public: EventValueInfo(const EVENT_MAP_INFO* pInfo, size_t index)

        // ��������� ���������� ���������
        : _pInfo(pInfo), _index(index) {}

    // ��������
    public: virtual ULONGLONG Value() const override 
    { 
        // ��������
        return _pInfo->MapEntryArray[_index].Value; 
    }
    // ��� ��������
    public: virtual PCWSTR Name() const override 
    {
        // ���������� �������� �����
        ULONG offset = _pInfo->MapEntryArray[_index].OutputOffset; 

        // ��������� ������� �����
        if (offset == 0) return nullptr; 
        
        // ������� ��� ��������
        return (PCWSTR)((PBYTE)_pInfo + offset); 
    }
};

class ProviderValueInfo : public ETW::IValueInfo
{ 
    // �������� �������� � ������ ��������
    private: const PROVIDER_FIELD_INFOARRAY* _pInfo; size_t _index; 

    // �����������
    public: ProviderValueInfo(const PROVIDER_FIELD_INFOARRAY* pInfo, size_t index)

        // ��������� ���������� ���������
        : _pInfo(pInfo), _index(index) {}

    // ��������
    public: virtual ULONGLONG Value() const override 
    { 
        // ��������
        return _pInfo->FieldInfoArray[_index].Value; 
    }
    // ��� ��������
    public: virtual PCWSTR Name() const override 
    {
        // ���������� �������� �����
        ULONG offset = _pInfo->FieldInfoArray[_index].NameOffset; 

        // ��������� ������� �����
        if (offset == 0) return nullptr; 
        
        // ������� ��� ��������
        return (PCWSTR)((PBYTE)_pInfo + offset); 
    }
    // �������� ��������
    public: virtual PCWSTR Description() const override 
    {
        // ���������� �������� ��������
        ULONG offset = _pInfo->FieldInfoArray[_index].DescriptionOffset; 

        // ��������� ������� ��������
        if (offset == 0) return nullptr; 
        
        // ������� �������� ��������
        return (PCWSTR)((PBYTE)_pInfo + offset); 
    }
};

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ��� �����
///////////////////////////////////////////////////////////////////////////////
class EventValueMap : public ETW::IValueMap
{ 
    // ����� � ������� �������� ����� 
    private: std::vector<BYTE> _buffer; std::vector<EventValueInfo> _map;

    // �����������
    public: EventValueMap(const EVENT_RECORD*, PCWSTR); 

    // ��� ��������
    public: virtual ETW::ValueMapType Type() const override
    {
        // ������������� ��� ������
        const EVENT_MAP_INFO* pInfo = (const EVENT_MAP_INFO*)&_buffer[0]; 

        // ��������� ��� ��������
        if ((pInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_BITMAP) != 0) return ETW::ValueMapType::Flag; 
        if ((pInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_BITMAP    ) != 0) return ETW::ValueMapType::Flag; 
        if ((pInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP  ) != 0)
        {
            // ��������� ��� ��������
            if ((pInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_FLAG  ) != 0) return ETW::ValueMapType::Flag;
        }
        return ETW::ValueMapType::Index;
    }
    // ����� ��������
    public: virtual size_t Count() const override { return _map.size(); } 
    // �������� �������� ��� �����
    public: virtual const ETW::IValueInfo& Item(size_t i) const override { return _map[i]; } 
};

class ProviderValueMap : public ETW::IValueMap
{ 
    // ����� � ������� �������� ����� 
    private: std::vector<BYTE> _buffer; std::vector<ProviderValueInfo> _map;

    // �����������
    public: ProviderValueMap(const GUID&, EVENT_FIELD_TYPE); 

    // ��� ��������
    public: virtual ETW::ValueMapType Type() const override
    {
        // ������������� ��� ������
        const PROVIDER_FIELD_INFOARRAY* pInfo = (const PROVIDER_FIELD_INFOARRAY*)&_buffer[0]; 

        // ������� ��� ��������
        return (pInfo->FieldType == EventKeywordInformation) ? ETW::ValueMapType::Flag : ETW::ValueMapType::Index; 
    }
    // ����� ��������
    public: virtual size_t Count() const override { return _map.size(); } 
    // �������� �������� ��� �����
    public: virtual const ETW::IValueInfo& Item(size_t i) const override { return _map[i]; } 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ���
///////////////////////////////////////////////////////////////////////////////
class BooleanType : public ETW::BooleanType
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // �������� �������� ��� �����
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // �����������
    public: BooleanType(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ���� �����
///////////////////////////////////////////////////////////////////////////////
class Int8Type : public ETW::Int8Type
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // �������� �������� ��� �����
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // �����������
    public: Int8Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class UInt8Type : public ETW::UInt8Type
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // �������� �������� ��� �����
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // �����������
    public: UInt8Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class Int16Type : public ETW::Int16Type
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // �������� �������� ��� �����
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // �����������
    public: Int16Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class UInt16Type : public ETW::UInt16Type
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // �������� �������� ��� �����
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // �����������
    public: UInt16Type(const class Event&, const EVENT_PROPERTY_INFO&);  
        
    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class Int32Type : public ETW::Int32Type
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // �������� �������� ��� �����
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // �����������
    public: Int32Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class UInt32Type : public ETW::UInt32Type
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // �������� �������� ��� �����
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // �����������
    public: UInt32Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class Int64Type : public ETW::Int64Type
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // �������� �������� ��� �����
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // �����������
    public: Int64Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class UInt64Type : public ETW::UInt64Type
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // �������� �������� ��� �����
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // �����������
    public: UInt64Type(const class Event&, const EVENT_PROPERTY_INFO&); 
        
    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class FloatType : public ETW::FloatType
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // �����������
    public: FloatType(const class Event& event, const EVENT_PROPERTY_INFO& info) : _event(event), _info(info) {}

    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
class DoubleType : public ETW::DoubleType
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // �����������
    public: DoubleType(const class Event& event, const EVENT_PROPERTY_INFO& info) : _event(event), _info(info) {}

    // ���������� ��� ������ � ������ ��������������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ��� ��������� ��� ����� ����������� ���������
///////////////////////////////////////////////////////////////////////////////
class PointerType : public ETW::PointerType
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 
    // �������� �������� ��� �����
    private: std::shared_ptr<ETW::IValueMap> _pValueMap; 

    // �����������
    public: PointerType(const class Event&, const EVENT_PROPERTY_INFO&);  

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� �������� �������� ��� �����
    public: virtual const ETW::IValueMap* GetValueMap() const override { return _pValueMap.get(); }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ��� �����
///////////////////////////////////////////////////////////////////////////////
class StringType : public ETW::StringType
{
    // ����� ������ � �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // �����������
    public: StringType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // ��������� ���������� ���������
        : _event(event), _info(info) {}

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 

    // ���������� ������ ������
    protected: virtual size_t GetLength(const ETW::IContainer*) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ��� �������
///////////////////////////////////////////////////////////////////////////////
class DateTimeType : public ETW::DateTimeType
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // �����������
    public: DateTimeType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // ��������� ���������� ���������
        : _event(event), _info(info) {}

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
 
class CimDateTimeType : public ETW::CimDateTimeType
{
    // �������� ������ � ������ ������������� �����
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; StringType _decoder;

    // �����������
    public: CimDateTimeType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // ��������� ���������� ���������
        : _event(event), _info(info), _decoder(event, info) {}

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 

    // ������ ������������� �����
    protected: virtual const BasicType& Decoder() const override { return _decoder; } 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ��� ������
///////////////////////////////////////////////////////////////////////////////
class BinaryType : public ETW::BinaryType
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info;

    // �����������
    public: BinaryType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // ��������� ���������� ���������
        : _event(event), _info(info) {}

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 

    // ���������� ������ ������
    protected: virtual size_t GetSize(const ETW::IContainer&) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ���� ������
///////////////////////////////////////////////////////////////////////////////
class GuidType : public ETW::GuidType
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // �����������
    public: GuidType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // ��������� ���������� ���������
        : _event(event), _info(info) {}

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

class SidType : public ETW::SidType
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // �����������
    public: SidType(const class Event& event, const EVENT_PROPERTY_INFO& info);  
        
    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

class IPv4Type : public ETW::IPv4Type
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // �����������
    public: IPv4Type(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // ��������� ���������� ���������
        : _event(event), _info(info) {}

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

class IPv6Type : public ETW::IPv6Type
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // �����������
    public: IPv6Type(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // ��������� ���������� ���������
        : _event(event), _info(info) {}

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};

class SocketAddressType : public ETW::SocketAddressType
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info; 

    // �����������
    public: SocketAddressType(const class Event& event, const EVENT_PROPERTY_INFO& info) 
        
        // ��������� ���������� ���������
        : _event(event), _info(info) {}

    // ���������� � ���������� ��� ������
    public: virtual USHORT InputType () const override { return _info.nonStructType.InType;  }
    public: virtual USHORT OutputType() const override { return _info.nonStructType.OutType; }

    // �������� ��������� �������������
    public: virtual BSTR ToString(const ETW::IContainer&, const void*, size_t) const override; 
};
///////////////////////////////////////////////////////////////////////////////
// ��� �������
///////////////////////////////////////////////////////////////////////////////
class ArrayType : public ETW::IArrayType
{
    // �������� ������
    private: const class Event& _event; const EVENT_PROPERTY_INFO& _info;
    // ��� ��������
    private: std::shared_ptr<ETW::IElementType> _pElementType; 

    // �����������
    public: ArrayType(const class Event& event, const EVENT_PROPERTY_INFO& info);  

    // �������� ���� ��������
    public: virtual const ETW::IElementType& ElementType() const override { return *_pElementType; }
    
    // ���������� ������ �������
    public: virtual size_t GetCount(const ETW::IContainer& parent) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��� ���������
///////////////////////////////////////////////////////////////////////////////
class StructType : public ETW::IStructType
{
    // ������������� � ������� �����
    private: GUID _id; std::vector<ETW::Field> _fields; 

    // �����������
    public: StructType(const class Event& event, size_t startIndex, size_t count); 

    // GUID ���������
    public: virtual REFGUID Guid() const override { return _id; }

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
    // ������� �������� 
    private: TDH_CONTEXT* _pContext; ULONG _cntContext; 
    // ������ � ���������� �������
    private: const EVENT_RECORD* _pEvent; std::vector<BYTE> _vecEventInfo;

    // ��� ���������
    private: std::unique_ptr<ETW::IStructType> _pStructType; 
    // ��������������� ���������
    private: std::unique_ptr<ETW::IStruct> _pStruct; 

    // �����������
    public: Event(TDH_CONTEXT* pContext, ULONG cntContext, const EVENT_RECORD* pEvent); 

    // ����� � ������ ������
    public: virtual const void* GetDataAddress() const override { return _pEvent->UserData;       }
    public: virtual size_t      GetDataSize   () const override { return _pEvent->UserDataLength; }

    // �������� ���������������� �������
    public: const TRACE_EVENT_INFO* GetEventInfo() const 
    {
        // �������� ���������������� �������
        return (const TRACE_EVENT_INFO*)&_vecEventInfo[0]; 
    }
    // �������� �������� �������� ��� �����
    public: std::shared_ptr<ETW::IValueMap> GetValueMap(const EVENT_PROPERTY_INFO& info) const; 

    // ��������������� ���������
    public: virtual const ETW::IStruct& Struct() const override { return *_pStruct; }

    // ������ ���������
    public: virtual size_t PointerSize() const override
    { 
        // ���������� ������ ���������
        if (_pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) return 4;
        if (_pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) return 8;

        // ������� ������ ���������
        return sizeof(void*); 
    }
    // ������� ������� ��� ������
    public: ETW::IBasicType* CreateBasicType(const EVENT_PROPERTY_INFO& info) const; 

    // �������� ��������� ������������� ��������
    public: std::wstring Format(const ETW::IContainer& parent, 
        const EVENT_PROPERTY_INFO& info, const void* pvData, size_t cbData) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ����������
///////////////////////////////////////////////////////////////////////////////
class ProviderInfo : public ETW::IProviderInfo
{
    // ������������� ���������� � �������� ��������� � �������
    private: GUID _id; ProviderValueMap _keywords; ProviderValueMap _levels;

    // �����������
    public: ProviderInfo(const GUID& id) : _id(id), 
        
        // ��������� �������� ��������� � �������
        _keywords(_id, EventKeywordInformation), _levels  (_id, EventLevelInformation) {} 

    // ������������� ����������
    public: virtual const GUID& ID() const { return _id; }

    // �������� �������� ��������� �����������
    public: virtual const ETW::IValueMap& Keywords() const override { return _keywords; }
    // �������� �������� ������� �����������
    public: virtual const ETW::IValueMap& Levels() const override { return _levels; }
}; 
}
