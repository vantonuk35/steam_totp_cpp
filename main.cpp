#include <iostream>
#include <bitset>
#include <vector>
#include "hmac.h"
#include "base64.h"
std::string get_steam_guard_login_code(std::string steamSharedSecret)
{
	const std::string SteamGuardChars = "23456789BCDFGHJKMNPQRTVWXY";//characters that are using in steam guard codes


	auto decodedSecret=base64_decode(steamSharedSecret);//shared_secret stored in base64 by default

	int64_t curTime = (time(0) / 30);//unix time without where we need half minute accuracy
	
	 std::string timeBinary(8, 0);
	 for (int i = 0; i < 4; i++) {//BigEndian translating 4byte integer to 4 string bytes 
		 timeBinary[i+4] = (curTime & (0xFF << (8 * (3-i)))) >> (8 * (3 - i));
	 }
	//time_binary 00 00 00 00 xx xx xx xx where x`s are time bytes
	auto HMACResult = hmac::get_hmac(decodedSecret, timeBinary);//get HMAC
	auto startByteOfInitialCodeIndex = HMACResult.back()&0x0F;//Get using bytes start point from last 4bits of hmac (0xF = 0b0000'1111)
	int32_t codeInitialInt=0;
	for(int i=0;i<4;i++)//BigEndian translating 4 string bytes to 4byte integer
	{
		codeInitialInt |= ((int)(HMACResult[startByteOfInitialCodeIndex+i]) & 0xFF) << ((3 - i) * 8);
	}


	codeInitialInt &=  0x7FFFFFFF;//throw off first bit (0x7f = 0b0111'1111)
	std::string code(5, '0');
	for(auto& c : code)
	{
		c = SteamGuardChars[codeInitialInt % SteamGuardChars.length()];
		codeInitialInt /= SteamGuardChars.length();//set correct characters from available
	}
	return code;
}
