#pragma once
#include <string>
#pragma warning(disable : 4996)
using namespace std;

wstring StringToWString(const string& str)

{
	std::wstring ws(str.size(), L' ');
	ws.resize(std::mbstowcs(&ws[0], str.c_str(), str.size()));
	return ws;
}

string hex_text(string test)
{
	string s = test;
	string ip_address;

	for (int i = 0; i < s.length(); i += 2)
	{
		char c[3] = { 0 };
		s.substr(i, 2).copy(c, 2, 0);
		int number = (int)strtol(c, NULL, 16);
		ip_address.push_back((char)number);
	}
	return ip_address;
}

wstring to_wstring(string const& str)
{
	size_t len = mbstowcs(nullptr, &str[0], 0);
	wstring wstr(len, 0);
	mbstowcs(&wstr[0], &str[0], wstr.size());
	return wstr;
}