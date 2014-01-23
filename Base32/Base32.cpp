//////////////////////////////////////////////////////////////////////
// Base32.cpp
// (c) Vasian Cepa http://madebits.com
//////////////////////////////////////////////////////////////////////

#include "Base32.h"

int Base32::GetEncode32Length(int bytes)
{
   int bits = bytes * 8;
   int length = bits / 5;
   if((bits % 5) > 0)
   {
      length++;
   }
   return length;
}

int Base32::GetDecode32Length(int bytes)
{
   int bits = bytes * 5;
   int length = bits / 8;
   return length;
}

static bool Encode32Block(unsigned char* in5, unsigned char* out8)
{
      // pack 5 bytes
      unsigned __int64 buffer = 0;
      for(int i = 0; i < 5; i++)
      {
		  if(i != 0)
		  {
			  buffer = (buffer << 8);
		  }
		  buffer = buffer | in5[i];
      }
      // output 8 bytes
      for(int j = 7; j >= 0; j--)
      {
		  buffer = buffer << (24 + (7 - j) * 5);
		  buffer = buffer >> (24 + (7 - j) * 5);
		  unsigned char c = (unsigned char)(buffer >> (j * 5));
		  // self check
		  if(c >= 32) return false;
		  out8[7 - j] = c;
      }
	  return true;
}

bool Base32::Encode32(unsigned char* in, int inLen, unsigned char* out)
{
   if((in == 0) || (inLen <= 0) || (out == 0)) return false;

   int d = inLen / 5;
   int r = inLen % 5;

   unsigned char outBuff[8];

   for(int j = 0; j < d; j++)
   {
      if(!Encode32Block(&in[j * 5], &outBuff[0])) return false;
      memmove(&out[j * 8], &outBuff[0], sizeof(unsigned char) * 8);
   }

   unsigned char padd[5];
   memset(padd, 0, sizeof(unsigned char) * 5);
   for(int i = 0; i < r; i++)
   {
      padd[i] = in[inLen - r + i];
   }
   if(!Encode32Block(&padd[0], &outBuff[0])) return false;
   memmove(&out[d * 8], &outBuff[0], sizeof(unsigned char) * GetEncode32Length(r));

   return true;
}

static bool Decode32Block(unsigned char* in8, unsigned char* out5)
{
      // pack 8 bytes
      unsigned __int64 buffer = 0;
      for(int i = 0; i < 8; i++)
      {
		  // input check
		  if(in8[i] >= 32) return false;
		  if(i != 0)
		  {
			  buffer = (buffer << 5);
		  }
		  buffer = buffer | in8[i];
      }
      // output 5 bytes
      for(int j = 4; j >= 0; j--)
      {
		  out5[4 - j] = (unsigned char)(buffer >> (j * 8));
      }
	  return true;
}

bool Base32::Decode32(unsigned char* in, int inLen, unsigned char* out)
{
   if((in == 0) || (inLen <= 0) || (out == 0)) return false;

   int d = inLen / 8;
   int r = inLen % 8;

   unsigned char outBuff[5];

   for(int j = 0; j < d; j++)
   {
      if(!Decode32Block(&in[j * 8], &outBuff[0])) return false;
      memmove(&out[j * 5], &outBuff[0], sizeof(unsigned char) * 5);
   }

   unsigned char padd[8];
   memset(padd, 0, sizeof(unsigned char) * 8);
   for(int i = 0; i < r; i++)
   {
      padd[i] = in[inLen - r + i];
   }
   if(!Decode32Block(&padd[0], &outBuff[0])) return false;
   memmove(&out[d * 5], &outBuff[0], sizeof(unsigned char) * GetDecode32Length(r));

   return true;
}

bool Base32::Map32(unsigned char* inout32, int inout32Len, unsigned char* alpha32)
{
	if((inout32 == 0) || (inout32Len <= 0) || (alpha32 == 0)) return false;
	for(int i = 0; i < inout32Len; i++)
	{
		if(inout32[i] >=32) return false;
		inout32[i] = alpha32[inout32[i]];
	}
	return true;
}

static void ReverseMap(unsigned char* inAlpha32, unsigned char* outMap)
{
	memset(outMap, 0, sizeof(unsigned char) * 256);
	for(int i = 0; i < 32; i++)
	{
		outMap[(int)inAlpha32[i]] = i;
	}
}

bool Base32::Unmap32(unsigned char* inout32, int inout32Len, unsigned char* alpha32)
{
	if((inout32 == 0) || (inout32Len <= 0) || (alpha32 == 0)) return false;
	unsigned char rmap[256];
	ReverseMap(alpha32, rmap);
	for(int i = 0; i < inout32Len; i++)
	{
		inout32[i] = rmap[(int)inout32[i]];
	}
	return true;
}