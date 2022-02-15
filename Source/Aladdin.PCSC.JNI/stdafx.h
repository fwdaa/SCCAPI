#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _SCL_SECURE_NO_WARNINGS

#include "..\..\Build\version.h"
#include <jni.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <list>
#include <map>

template <typename T, typename Allocator>
inline const T* data(const std::vector<T, Allocator>& vec)
{
	// ������� ����� ������
	return vec.empty() ? 0 : &vec[0];
}

template <typename T, typename Allocator>
inline T* data(std::vector<T, Allocator>& vec)
{
	// ������� ����� ������
	return vec.empty() ? 0 : &vec[0];
}
