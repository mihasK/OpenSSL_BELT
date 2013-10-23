/*!
*******************************************************************************
\file btls_mem.h
\brief ����������� ������� ������ � ������� 
*//****************************************************************************
\author (�) ����� ���������� http://apmi.bsu.by
\created 2013.08.01
\version 2013.09.26
*******************************************************************************
*/

#ifndef _BELT_MEM_H_
#define _BELT_MEM_H_

#include <memory.h>
#include <string.h>
#include <malloc.h>

#define memCopy(dest, src, count) memcpy(dest, src, count)

#define memMove(dest, src, count) memmove(dest, src, count)

#define memCmp(src1, src2, count) memcmp(src1, src2, count)

#define memSet(dest, c, count) memset(dest, c, count)

#define memSetZero(dest, count) memSet(dest, 0, count)

#endif /* MEM_H_ */
