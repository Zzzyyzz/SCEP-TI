/**
 * @file libFlow2SE.h (https://www.seu.edu.cn/) 
 * @author hwu(hwu@seu.edu.cn), caymanhu(caymanhu@qq.com)
 * @brief flows statistics，流数据统计
 * @version 0.1
 * @date 2021-11-22
 */
#ifndef LIB_FLOW2_SE_H
#define LIB_FLOW2_SE_H

#include <vector>
#include "libFlowBaseSE.h"

class IFlow2Stat
{
public:
    virtual ~IFlow2Stat(){}
public://如果需要大改，可以重载函数
    /**
     * @brief 按传入时间，抽样遍历，可以遍历不同时间窗口，比如10，20，40，80。
     * 
     */
    virtual bool iter_smp_pcap_bytime(int ratio, int beginP, double time, bool bClear, bool bfin) = 0;

    /**
     * @brief 按传入时间，遍历，可以遍历不同时间窗口，比如10，20，40，80。
     * 
     * @return true 
     * @return false 
     */
    virtual bool iterPcapByTime(double time, bool bClear, bool bfin) = 0;

    /**
     * @brief 按时间区间（起始点，结束点） 遍历
     * 
     * @return true 
     * @return false 
     */
    virtual bool iterPcap_interval(double btime, double etime) = 0;

    /**
     * @brief 遍历
     * 
     * @return true 
     * @return false 
     */
    virtual bool iterPcap(int type=0) = 0;

    /**
     * @brief 按 “时间段” 遍历
     * 
     * @return true 
     * @return false 
     */
    virtual bool iterPcapByEpoch(double lenEpoch, bool bClear, int maxEpoch = 0) = 0;

    /**
     * @brief 抽样遍历pcap文件
     * 
     * @param ratio 抽样比
     * @param beginP 抽样num
     * @return true 
     * @return false 
     */
    virtual bool iterSamplePcap(int ratio, int beginP) = 0;

    /**
     * @brief 按时间片段抽样遍历pcap文件
     * 
     * @param ratio 抽样比
     * @param beginP 抽样num
     * @return true 
     * @return false 
     */
    virtual bool iterSmpPcapByEpoch(int ratio, int beginP, double lenEpoch, bool bClear, int maxEpoch = 0) = 0;

    /**
     * 遍历数据，流是否需要删除。type---reserved
    */
    virtual bool traverse_flows(int type) = 0;

    /**
     * @brief 分组处理函数。
     * @param lppck 分组指针
     * @return true 处理成功
     * @return false 
     */    
    virtual bool dealPacket(CPacket* lppck, int type = 0) = 0;

    /**
     * @brief 遍历完毕后，存储数据
     * 
     * @param cntPck pcap总分组个数
     * @return true 
     * @return false 
     */
    virtual bool saveData(uint64_t cntPck, bool bFin) = 0;

    /**
     * @brief Get the Elephant object
     * 
     * @return std::vector<IFlow2Object*>* 
     */
    virtual std::vector<IFlow2Object*>* getElephant() = 0;
public:
    /**
     * @brief 该接口子类所需的内容检测
     * 
     * @return true 成功，可以使用
     * @return false 失败，不能使用
     */
    virtual bool isChecked() = 0;

    /**
     * @brief Set the Parameters
     * 
     * @param stat_type 统计的种类: {pso_IPPort=0, pso_IPPortPair, pso_IP, pso_IPPair, pso_MACSubnet, pso_MACSubnetPair, pso_MAC, pso_MACPair}
     * @param protocol 协议,bit数据: 1 -- TCP，2 -- UDP，3 -- TCP+UDP
     * @param stattype 统计流的方法: {psm_Unique=0, psm_SouDstSingle, psm_SouDstDouble, psm_filter, psm_SD_forward, psm_SD_backward}
     * @param bPayload true -- 统计 payload length>0 的数据 ， false -- 统计 payload length>=0 的数据
     */
    virtual bool setParameter(packet_statistics_object_type stat_type, int protocol, packet_statistics_method method, bool bPayload) = 0;

    /**
     * @brief Set the object Creator 
     * 
     * @param lpFIC -- IFlow2Object creator，
     */
    virtual void setCreator(IFlow2ObjectCreator* lpFOC) = 0;

    virtual double getReadTime() = 0;
};


/**
 * @brief 统计工具类
 */
class CFlow2StatCreator
{
public:
    /**
     * @brief Create a flow2 statistics
     * 
     * @param fname pcap文件名
     * @param bit hash计算占比特位，建一个2^bit的hash表
     * @param elephant 大流统计的阈值，超过的大流才会被统计
     * @return IFlow2Stat* 
     */
    static IFlow2Stat* create_flow2_stat(std::string fname, int bit, int elephant, int hash_m);
};


#endif
