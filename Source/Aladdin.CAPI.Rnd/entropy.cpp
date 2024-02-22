#include "stdafx.h"
#include "stsnist.h"
#include "cprob.h"  
#include <exception>
#include <vector>

////////////////////////////////////////////////////////////////////////////////////
// ��������� ���������� phi
////////////////////////////////////////////////////////////////////////////////////
static double phi(const BitSequence* epsilon, size_t n, size_t m)
{
	// ���������� ������� ������
	if (m == 0) return 0.0; size_t mask = (size_t(1) << m) - 1; 

	// �������� ������ ��� ������
	std::vector<size_t> nu(mask + 1); size_t value = 0; double sum = 0; 

	// ��� ���� ���������� ���� (��������� 2.12.4.2)
	for (size_t i = 0; i < n + m - 1; i++)
	{
		// ���������� �������� m-�������
		value = ((value << 1) ^ epsilon[i % n]) & mask; 

		// ��������� �������
		if (i >= m - 1) nu[value]++; 
	}
	// ��� ���� ������
	for (size_t i = 0; i < nu.size(); i++)
	{
		// ��������� ����������� ����������������
		if (nu[i] == 0) continue; 

		// ������� ���������� ���������
		sum += (double)nu[i] * log((double)nu[i] / n); 
	}
	// ��������� ���������� 2.12.4.3
	return sum / n; 
}

////////////////////////////////////////////////////////////////////////////////////
// 2.12 Approximate Entropy Test 
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf
////////////////////////////////////////////////////////////////////////////////////
bool EntropyTest(const BitSequence* epsilon, size_t n, size_t m)
{
	try { 
		// ��������� 2.12.4.3
		double phim0 = phi(epsilon, n, m    );
		double phim1 = phi(epsilon, n, m + 1);

		// ��������� 2.12.4.4
		double chi2 = 2.0 * n * (log(2.0) - (phim0 - phim1));

		// ��������� 2.12.4.5
		double p_value = igamc(pow(2.0, (double)(m - 1)), chi2 / 2);
	
		// ��������� 2.12.5
		return (p_value >= 0.01); 
	}
	// ���������� ��������� ������
	catch (const std::exception &) { return false; }
}