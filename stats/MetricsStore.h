/****************************** Module Header ******************************\
* Module Name:  StatisticStore.h
* Project:      Chrupcio
* Copyright     Grzegorz Kasprzyszak
*
* Provides a class to store statistics
\***************************************************************************/

#pragma once


class CStatisticStore
{
public:
    CStatisticStore(PWSTR pszStatisticStoreName);

    // Statistic object destructor. 
    virtual ~CStatisticStore(void);

    void createEntry(PWSTR pshStatisticName)

protected:

private:
};