#include "stdafx.h"
#include "Store.h"

Aladdin::CAPI::Container^ Aladdin::CAPI::STB::Avest::CSP::SCardStore::CreateContainer(
	ContainerInfo^ info, Authentication^ authentication)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::SCardStore::CreateContainer); 
	
	// ������� ������� �������
	CAPI::ProviderStore::CreateContainer(info, authentication); 

	// ���������� ��������� ����������
	CAPI::CSP::ProviderHandle hProvider = ((CAPI::CSP::Provider^)Provider)->Handle; 

	// ������� ��������� � �������������� ����������
	CAPI::CSP::ContainerHandle hContainer = hProvider.AcquireContainer(info->UniqueName, CRYPT_NEWKEYSET); 

	// ������� ������ ����������
	return gcnew CAPI::CSP::Container(info, hContainer, 0, authentication);		
}

void Aladdin::CAPI::STB::Avest::CSP::SCardStore::DeleteContainer(
	ContainerInfo^ info, Authentication^ authentication)
{
	ATRACE_SCOPE(Aladdin::CAPI::STB::Avest::CSP::SCardStore::DeleteContainer); 

	// ���������� ��������� ����������
	CAPI::CSP::ProviderHandle hProvider = ((CAPI::CSP::Provider^)Provider)->Handle; 

	// ������� ��������� � �������������� ����������
	hProvider.DeleteContainer(info->UniqueName, 0); 

	// ������� ������� �������
	CAPI::CSP::ProviderStore::DeleteContainer(info, authentication); 
}
