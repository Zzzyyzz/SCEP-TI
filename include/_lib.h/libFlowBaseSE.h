/**
 * @file libFlowBaseSE.h (https://www.seu.edu.cn/) 
 * @author hwu(hwu@seu.edu.cn), caymanhu(caymanhu@qq.com)
 * @brief flows statistics，流数据统计
 * @version 0.1
 * @date 2023-07
 */
#ifndef LIB_FLOW_BASE_SE_H
#define LIB_FLOW_BASE_SE_H

#include <cstdlib>
#include <cstring>
#include <string>
#include <stdint.h> 
#include "libPcapSE.h"
#include "libBaseSE.h"

/**
 * hashtable中统计的flow类
*/
class IFlow2Object
{
public:
    virtual ~IFlow2Object() {}
public:
    /**
     * @brief 检测flow object构造是否成功
     * 
     * @return true 
     * @return false 
     */
    virtual bool checkObject() = 0;

    /**
     * @brief 通过key判断是否是该object
     * 
     * @param buf packet key
     * @param len key长度
     * @return true 
     * @return false 
     */
    virtual bool isSameObject(uint8_t* buf, int len) = 0;

    /**
     * @brief 增加一个packet
     * 
     * @param lppck packet指针
     * @param bSou true--forward, false--backward 
     * @return true 
     * @return false 
     */
    virtual bool addPacket(CPacket* lppck, bool bSou) = 0;

    /**
     * @brief 被放入到大流队列。
     * 
     * @param lppck 
     * @return true 
     * @return false 
     */
    virtual bool intoElephant(CPacket* lppck){return true;}

    /**
     * 多次遍历数据前使用，看是否合规。
     * 第一次遍历后，hashtable里面的流可以做标记。
    */
    virtual bool check_flow() {return true;}

    /**
     * @brief save Object
     * 
     * @param fp 文件指针
     * @param cnt 总数
     * @param bFin 用于epoch统计，是否时结尾
     * @return true 
     * @return false 
     */
    virtual bool saveObject(FILE* fp, uint64_t cnt, bool bFin) = 0;
public://被动调用函数
    virtual uint32_t getPckCnt() = 0;
    virtual void incPckCnt() = 0;
};

class IFlow2ObjectCreator
{
public:
    virtual ~IFlow2ObjectCreator() {}
public:
    /**
     * @brief Create a Object 
     * 
     * @param buf object内存数据指针
     * @param len object数据长度
     * @return IFlow2Object* 返回IFlow2Object接口指针
     */
    virtual IFlow2Object* create_Object(uint8_t* buf, int len) = 0;

    /**
     * @brief 如果parameter的method是psm_filter，stat遍历时会调用该过滤函数，需要复写。
     * 
     * @param lppck packet指针
     * @return int 1--作为forward数据处理，2--作为backward数据处理，3--双向数据处理，0--不处理
     */
    virtual int filter_packet(CPacket* lppck){return 0;}
public:    
    /**
     * @brief 结果存储文件名
     * 
     * @return std::string 
     */
    virtual std::string getName() = 0;

    /**
     * @brief 统计方法
     * 
     * @return packet_statistics_object_type 
     */
    virtual packet_statistics_object_type getStatType() = 0;

    /**
     * @brief 是否需要stat存储
     * 
     * @return true 
     * @return false 
     */
    virtual bool isSave() = 0;

public:
    virtual void beginStat(int num){}
    virtual void endStat(int num){}
};

#endif
