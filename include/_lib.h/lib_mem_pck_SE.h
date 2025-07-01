/**
 * @file lib_mem_pck.h (https://www.seu.edu.cn/) 
 * @author hwu(hwu@seu.edu.cn), caymanhu(caymanhu@qq.com)
 * @brief memory packet
 * @version 0.1
 * @date 2024-11-7
 */

#ifndef LIB_MEM_PCK_SE_H
#define LIB_MEM_PCK_SE_H

#include <cstdlib>
#include <cstring>
#include <stdint.h>
#include <string>
#include "libPacketSE.h"

/**
 * @brief packet memory database interface
 */
class I_memory_packet_DB
{
public:
    /**
     * @brief Destroy 
     * 
     */
    virtual ~I_memory_packet_DB(){}
public:
    /**
     * @brief 得到内存库中数据包数量
     * 
     * @return uint64_t 
     */
    virtual uint64_t get_pck_num() = 0;
    virtual int get_DB_num() = 0;


    /**
     * @brief 给库分配内存
     * 
     * @return true 
     * @return false 
     */
    virtual bool alloc_mem() = 0;

    /**
     * @brief 清空内存库
     * 
     * @return true 
     * @return false 
     */
    virtual bool clear_DB() = 0;
    virtual void read_DB() = 0;

    /**
     * @brief 增加一个数据包进库
     * 
     * @param pck packet pointer
     * @return true 
     * @return false 
     */
    virtual bool add_packet(CPacket* pck) = 0;

    /**
     * @brief 移到下一个数据包
     * 
     * @return true 
     * @return false 
     */
    virtual bool next_packet() = 0;

    /**
     * @brief 得到当前数据包
     * 
     * @return CPacket* 
     */
    virtual CPacket* read_packet() = 0;
};

/**
 * @brief 
 */
class mem_packet_DB_creator
{
public:
    /**
     * @brief 构造一个内存数据包库
     * @param size memory size, 2G * size
     * @param type packet type, 0: only head, 1: head + payload
     * @return I_memory_packet* 
     */
    static I_memory_packet_DB* create_mem_pck_DB(int size, int type);
};

#endif
