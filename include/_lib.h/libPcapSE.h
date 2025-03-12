/**
 * @file libPcapSE.h (https://www.seu.edu.cn/) 
 * @author hwu(hwu@seu.edu.cn), caymanhu(caymanhu@qq.com)
 * @brief pcap or pcapng file
 * @version 0.1
 * @date 2021-09-03
 */
#ifndef LIB_PCAP_SE_H
#define LIB_PCAP_SE_H

#include <cstdlib>
#include <cstring>
#include <stdint.h>
#include <string>
#include "libPacketSE.h"

/**
 * @brief reader接口
 */
class CReader
{
public:
    /**
     * @brief Destroy the CReader object
     * 
     */
    virtual ~CReader(){}
public:
    /**
     * @brief open pcap file
     * 
     * @return true 
     * @return false 
     */
    virtual bool openPcap() = 0;

    /**
     * @brief read packet
     * 
     * @return int 
     */
    virtual int readPacket() = 0;

    /**
     * @brief next packet
     * 
     * @return int 
     */
    virtual int nextPacket() = 0;

    /**
     * @brief Get the Packet pointer
     * 
     * @return CPacket* 
     */
    virtual CPacket* getPacket() = 0;
public:
    /**
     * @brief have MAC for linktype 101 or linux
     * 
     * @return true 
     * @return false 
     */
    virtual bool haveMACData() = 0;

    /**
     * @brief Get the Error 
     * 
     * @return int 
     */
    virtual int getError() = 0;

    /**
     * @brief Get the Base TM
     * 
     * @return double 
     */
    virtual double getBaseTM() = 0;

    /**
     * @brief Get the read file time
     * 
     * @return double 
     */
    virtual double getReadTime() = 0;
};

/**
 * @brief writer接口
 */
class CWriter
{
public:
    /**
     * @brief Destroy the CWriter
     * 
     */
    virtual ~CWriter(){}
public:
    /**
     * @brief Get the Pck Number
     * 
     * @return int 
     */
    virtual int getPckNum() = 0;

    /**
     * @brief open writer
     * 
     * @return true 
     * @return false 
     */
    virtual bool openWriter() = 0;

    /**
     * @brief close writer
     * 
     */
    virtual void closeWriter() = 0;

    /**
     * @brief add new packet into pcap
     * 
     * @param pck packet pointer
     * @return true 
     * @return false 
     */
    virtual bool addPacket(CPacket* pck) = 0;
};

/**
 * @brief 依序reader接口
 */
class CSquReader
{
public:
    /**
     * @brief Destroy the CSquReader object
     * 
     */
    virtual ~CSquReader(){}
public:
    /**
     * @brief open pcap
     * 
     * @return true 
     * @return false 
     */
    virtual bool openPcap() = 0;

    /**
     * @brief read packet
     * 
     * @return int 
     */
    virtual int readPacket() = 0;

    /**
     * @brief Get the Packet pointer
     * 
     * @return CPacket* 
     */
    virtual CPacket* getPacket() = 0;
public:
    /**
     * @brief 依时间定位squ pcap
     * 
     * @param time 
     * @return true 
     * @return false 
     */
    virtual bool findSquPcap(double time) = 0;

    /**
     * @brief check squ pcap files
     * 
     * @return true 
     * @return false 
     */
    virtual bool checkSquPcap() = 0;
public:
    /**
     * @brief Set the Message
     * 
     * @param bm 
     */
    virtual void setMsg(bool bm) = 0;
};

extern "C"
{
/**
 * @brief Create a pcap reader 
 * 
 * @param filename 
 * @return CReader*  
 */
CReader* create_pcap_reader(const char* filename);

/**
 * @brief Create a pcap writer 
 * 
 * @param filename 
 * @param type  0:不写入payload, 1:写入payload
 * @param linktype 
 * @return CWriter* 
 */
CWriter* create_pcap_writer(const char* filename, int type, int linktype=1);

/**
 * @brief Create a squ pcap reader 
 * 
 * @param filename 
 * @return CSquReader* 
 */
CSquReader* create_squ_pcap_reader(const char* filename, int chg_time = 0);
}

#endif
