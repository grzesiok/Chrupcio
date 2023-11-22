/****************************** Module Header ******************************\
* Module Name:  StatisticEntry.h
* Project:      Chrupcio
* Copyright     Grzegorz Kasprzyszak
*
* Provides a class describe Statistic
\***************************************************************************/

#pragma once


class CStatisticEntry
{
public:
    CStatisticEntry(PWSTR pszStatisticStoreName);

    virtual ~CStatisticEntry(void);

    DWORD getValue(void);

protected:
    virtual DWORD update(value DWORD);

private:
};