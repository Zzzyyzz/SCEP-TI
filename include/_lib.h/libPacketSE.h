/**
 * @file libPacketSE.h (https://www.seu.edu.cn/) 
 * @author hwu(hwu@seu.edu.cn), caymanhu(caymanhu@qq.com)
 * @brief packet library, link with libPcap or libPcapSE
 * @version 0.1
 * @date 2022-01-15
 */
#ifndef LIB_PACKET_SE_H
#define LIB_PACKET_SE_H

#include <cstdlib>
#include <cstring>
#include <stdint.h>
#include <string>
#include <sys/time.h>

struct timeVS
{
    uint32_t            tv_sec;
    uint32_t            tv_usec;
};

/**
 * @brief 数据报接口
 */
class CPacket
{
public:
    static const int lenIPV6 = 16;    
    static const int lenMAC = 6;
    static const int MAX_PACKET_LEN = 131072;
public:
    /**
     * @brief Destroy the CPacket object
     * 
     */
    virtual ~CPacket(){}
public:                 //time
    /**
     * @brief Get the Packet GMT Time
     * 
     * @return double GMT time
     */
    virtual double      getPckGMTTime() = 0;

    /**
     * @brief Get the Packet GMT time point
     * 
     * @return GMT time
     */
    virtual timeVS      getPckGMTTimeval() = 0;

    /**
     * @brief Get the Packet Offset Time 
     * 
     * @return double  offset time
     */
    virtual double      getPckOffTime() = 0;

    virtual timeVS      get_pck_offset_tmvs() = 0;

    /**
     * @brief Get the pcap first packet GMT Time
     * 
     * @return double begin time
     */
    virtual double      get_begin_time() = 0;
public:                 //protocol, IP, port
    /**
     * @brief Get the Protocol 
     * 
     * @return uint8_t 
     */
    virtual uint8_t     getProtocol() = 0;

    /**
     * @brief get ip version
     * 
     * @return uint8_t 4,6
     */
    virtual uint8_t     getIPVer() = 0;

    /**
     * @brief Get the Src IP v4
     * 
     * @return uint32_t 
     */
    virtual uint32_t    getSrcIP4() = 0;

    /**
     * @brief Get the Dst IP v4
     * 
     * @return uint32_t 
     */
    virtual uint32_t    getDstIP4() = 0;

    /**
     * @brief Get the Src IP v6
     * 
     * @return uint8_t* 
     */
    virtual uint8_t*    getSrcIP6() = 0;

    /**
     * @brief Get the Dst IP v6
     * 
     * @return uint8_t* 
     */
    virtual uint8_t*    getDstIP6() = 0;
    
    /**
     * @brief Get the Src Port
     * 
     * @return uint16_t 
     */
    virtual uint16_t    getSrcPort() = 0;

    /**
     * @brief Get the Dst Port
     * 
     * @return uint16_t 
     */
    virtual uint16_t    getDstPort() = 0;
public:                 //length
    /**
     * @brief Get the Length Frame Header 
     * 
     * @return int 
     */
    virtual int         getLenFrameHeader() = 0;

    /**
     * @brief Get the Len IP Header 
     * 
     * @return int 
     */
    virtual int         getLenIPHeader() = 0;

    /**
     * @brief Get the Len TCP Header 
     * 
     * @return int 
     */
    virtual int         getLenTCPHeader() = 0;

    /**
     * @brief Get the Len UDP Header
     * 
     * @return int 
     */
    virtual int         getLenUDPHeader() = 0;

    /**
     * @brief Get the Len Header sum
     * 
     * @return int 
     */
    virtual int         getLenHeader() = 0;

    /**
     * @brief Get the Len  IP + TCP(UDP) Header sum
     * 
     * @return int 
     */
    virtual int         getLen_IP_P_Header() = 0;

    /**
     * @brief Get the Len Total
     * 
     * @return int 
     */
    virtual int         getLenTotal() = 0;

    /**
     * @brief Get the Len Capture
     * 
     * @return int 
     */
    virtual int         getLenCap() = 0;

    /**
     * @brief Get the Len of Packet's payload
     * 
     * @return int 
     */
    virtual int         getLenPayload() = 0;

    /**
     * @brief Get the Length of Packet(传输长度)
     * 
     * @return int 
     */
    virtual int         getLenPck() = 0;
public:                 //MAC
    /**
     * @brief Get the Src MAC 
     * 
     * @return uint8_t* 
     */
    virtual uint8_t*    getSrcMAC() = 0;

    /**
     * @brief Get the Dst MAC
     * 
     * @return uint8_t* 
     */
    virtual uint8_t*    getDstMAC() = 0;
public:                 //TCP
    /**
     * @brief get TCP flag
     * 
     * @return uint8_t 
     */
    virtual uint8_t     getTCPFlag() = 0;

    /**
     * @brief get TCP RWND value (scale not included)
     * 
     * @return uint8_t 
     */
    virtual uint16_t     getTCP_RWND() = 0;

    /**
     * @brief get TCP sack ??? 尚未完成
     * 
     * @return uint32_t 
     */
    virtual uint32_t    getACKSACK() = 0;

    /**
     * @brief get TCP sack 个数
     * 
     * @return int 
     */
    virtual int         getSACKCount() = 0;

    /**
     * @brief 是否有time stamp
     * 
     * @return true 
     * @return false 
     */
    virtual bool        haveTimeStamp() = 0;

    /**
     * @brief get TCP options 数据
     * 
     * @param len 返回长度
     * @return uint8_t* 数据指针
     */
    virtual uint8_t*    getTCPOptions(int& len) = 0;

    /**
     * @brief get TCP header data
     * 
     * @param len return length
     * @return uint8_t* Data pointer
     */
    virtual uint8_t*    getTCPHeader(int& len) = 0;

    /**
     * @brief get TCP sequence
     * 
     * @return uint32_t sequence
     */
    virtual uint32_t getSelfSeq() = 0;
    virtual uint32_t getAckSeq() = 0;
public:                 //buffer
    /**
     * @brief Get the Packet Payload data
     * 
     * @param len return length
     * @return uint8_t* Data pointer
     */
    virtual uint8_t*    getPacketPayload(int& len) = 0;

    /**
     * @brief Get the Packet Buffer 
     * 
     * @param len return length
     * @param type capture type
     * @return uint8_t* Data pointer
     */
    virtual uint8_t*    getPacketBuffer(int &len, int type) = 0;

    /**
     * @brief Get IP Packet Buffer 
     * 
     * @param len return length
     * @param type capture type
     * @return uint8_t* Data pointer
     */
    virtual uint8_t*    getIPPckBuffer(int &len, int type) = 0;

    virtual uint8_t*    getEthernetHead() = 0;
    virtual uint8_t*    getBuffer() = 0;
    virtual void        setBuffer(uint8_t* lp_pos) = 0;
public:
    /**
     * @brief Set the pcap_pkthdr
     * 
     * @param time second + microsecond
     * @param caplen capture length
     * @param pcklen packet length
     */
    virtual void        set_pck_header_info(long time_high, long time_low, uint32_t caplen, uint32_t pcklen) = 0;

    /**
     * @brief Set the Packet GMT Time
     * 
     * @param tm GMT time
     */
    virtual void        setPckGMTTime(double tm) = 0;

    /**
     * @brief set the pcap first packet GMT Time (for SquReader)
     * 
     * @param tm begin time
     */
    virtual void       set_begin_time(long tm_high, long tm_low) = 0;

    /**
     * @brief Set the Src MAC
     * 
     * @param buf 
     */
    virtual void        setSrcMAC(uint8_t* buf) = 0;

    /**
     * @brief Set the Dst MAC
     * 
     * @param buf 
     */
    virtual void        setDstMAC(uint8_t* buf) = 0;

    /**
     * @brief writer时，MAC数据被改过，需要运行此函数
     * 
     */
    virtual void        modifyFrameLayerData() = 0;

    /**
     * @brief Set the Src IP v4
     * 
     * @param ip 
     */
    virtual void        setSrcIP4(uint32_t ip) = 0;

    /**
     * @brief Set the Dst IP v4
     * 
     * @param ip 
     */
    virtual void        setDstIP4(uint32_t ip) = 0;

    /**
     * @brief writer时，IP数据被改过，需要运行
     * 
     */
    virtual void        modifyIPLayerData() = 0;

    /**
     * @brief Set the Src port
     * 
     * @param ip 
     */
    virtual void        setSrcPort(uint16_t port) = 0;

    /**
     * @brief Set the Dst port
     * 
     * @param ip 
     */
    virtual void        setDstPort(uint16_t port) = 0;

    /**
     * @brief writer时，IP数据被改过，需要运行
     * 
     */
    virtual void        modifyTransportLayerData() = 0;
public:                 //other
    /**
     * @brief Get the Pck Number 
     * 
     * @return uint64_t 
     */
    virtual uint64_t    getPckNum() = 0;

    /**
     * @brief set the Pck Number 
     * 
     * @param num packet number 
     */
    virtual void        setPckNum(uint64_t num) = 0;

    /**
     * @brief Get the Capture Type
     * 
     * @return int 
     */
    virtual int         getCapType() = 0;
public:
    /**
     * @brief get packet detail from Pcap file
     * @param   pos---起点
     * @param   len---长度
     * @param   linktype---pcap file link type  
     * 
     * @return int TCP -- 6, UDP -- 17 ...
     */
    virtual int         getPckDetailFromPcapFile(int pos, int len, uint32_t linktype) = 0;

    /**
     * @brief get packet detail from buffer
     * @param   lpbuf---内存指针
     * @param   len---长度
     * @param   linktype---pcap file link type  
     * 
     * @return int TCP -- 6, UDP -- 17 ...
     */
    virtual int         getPckDetailFromBuffer(const uint8_t* lpbuf, int len, uint32_t linktype) = 0;
};

//======================================================================================================================
//======================================================================================================================
//======================================================================================================================
//======================================================================================================================
//======================================================================================================================
//======================================================================================================================
//======================================================================================================================

/**
 * @brief 工具类(全静态函数)
 */
class CPacketTools
{
public:                 //invert
    /**
     * @brief uint16_t字节序更换
     * 
     * @param dd 
     * @return uint16_t 
     */
    static uint16_t     invUint16(uint16_t dd);

    /**
     * @brief uint32_t字节序更换
     * 
     * @param dd 
     * @return uint32_t 
     */
    static uint32_t     invUint32(uint32_t dd);
public:                 // to string
    /**
     * @brief IPV4转字符串
     * 
     * @param ip 
     * @param str 
     */
    static void         IPV4_toString(uint32_t ip, char* str);

    /**
     * @brief IPv6转字符串
     * 
     * @param ip6 
     * @param str 
     * @param bfile
     */
    static void         IPV6_toString(uint8_t* ip6, char* str, int bfile=0);

    /**
     * @brief MAC址转字符串
     * 
     * @param mac 
     * @param str 
     */
    static void         MAC_toString(uint8_t* mac, char* str, int bfile=0);

    /**
     * @brief IPv4子网转字符串
     * 
     * @param ip 
     * @param str 
     */
    static void         IPV4Subnet_toStr(uint32_t ip, char* str, int ibc = 0, int type=0);

    /**
     * @brief IPV6子网转字符串
     * 
     * @param ip6 
     * @param str 
     */
    static void         IPV6Subnet_toStr(uint8_t* ip6, char* str, int bfile=0, int type=0);

    /**
     * @brief IPV6文件名字符串
     * 
     * @param ip6 
     * @param str 
     */
    static void         IPV6_toFilename(uint8_t* ip6, char* str);
public:                 // to hash buffer
    /**
     * @brief Get the HashBuf (prot + IP + 异向MAC)
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IPMAC(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf (MAC + 同向Subnet)
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_MACSubnet(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf (MAC + 同向Subnet B类)
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_MACSubnetB(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf (MAC + 同向Subnet)对
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_MACSubnetpair(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf (MAC + 同向Subnet B类)对
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_MACSubnetBpair(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf (MAC)
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_MAC(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf (MAC)对
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_MACpair(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf (protocol + IP)
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IP(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf (IP)
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IP_noprot(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf  protocol +IP对
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IPpair(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf  (IP对)
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IPpair_noprot(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf protocol + IP + port
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IPport(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf protocol + IP_A + port_B
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IPA_portB(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);


    /**
     * @brief Get the HashBuf protocol + (IP +port)pair
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IPportpair(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf protocol + sou IP + dst subnet_B
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--only true 只能统计一个方向
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IP_subnetB(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf protocol + sou subnet_B + dst IP
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--only true 只能统计一个方向
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_subnetB_IP(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf protocol + sou IP + dst subnet_C
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--only true 只能统计一个方向
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IP_subnetC(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf protocol + sou subnet_C + dst IP
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--only true 只能统计一个方向
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_subnetC_IP(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the HashBuf port
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_port(CPacket* lpPck, uint8_t* buf, int &len, bool bSou);

    /**
     * @brief Get the Packet Hash Buf object
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param type 种类
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getPacketHashBuf(CPacket* lpPck, uint8_t* buf, int &len,  int type, bool bSou);

    /**
     * @brief Get the Hash Buf IP + port
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst
     * @return true 
     * @return false 
     */
    static bool         getIppHashBuf(CPacket* lppck, uint8_t* buf, int &len,  bool bSou);

    /**
     * @brief Get the HashBuf protocol + IP(小) + port + IP(大) + port, unique order by IP
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst 返回
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_flow_unique(CPacket* lpPck, uint8_t* buf, int &len, bool &bSou);

    /**
     * @brief Get the HashBuf protocol + IP(小) + IP(大) , unique order by IP
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst 返回
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IPflow_unique(CPacket* lpPck, uint8_t* buf, int &len, bool &bSou);

    /**
     * @brief Get the HashBuf IP(小) + IP(大) , unique order by IP
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst 返回
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_IPflow_noprot_unique(CPacket* lpPck, uint8_t* buf, int &len, bool &bSou);

    /**
     * @brief Get the HashBuf protocol + MAC(小) + subnet + MAC(大) +subnet, unique order by MAC
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst 返回
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_MACsubnet_unique(CPacket* lpPck, uint8_t* buf, int &len, bool &bSou);

    /**
     * @brief Get the HashBuf protocol + MAC(小) + MAC(大), unique order by MAC
     * 
     * @param lpPck 分组指针
     * @param buf hash buffer
     * @param len 长度返回
     * @param bSou true--sou， false--dst 返回
     * @return true 
     * @return false 
     */
    static bool         getHashBuf_MAC_unique(CPacket* lpPck, uint8_t* buf, int &len, bool &bSou);
public:                 //hash buffer -> string
    /**
     * @brief Get the protocol+(IP+port)pair string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_IPportpair_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the protocol + IP + port string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_IPport_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the protocol + IP pair string from hash buffer
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_IPpair_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the IP pair string from hash buffer
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_IPpair_noprot_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the protocol + IP string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_IP_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the IP string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_IP_noprot_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the Str (MAC+Subnet)pair string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_MACSubnetpair_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the MAC + Subnet string from hash buffer  
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_MACSubnet_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the MAC pair string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_MACpair_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the MAC string from hash buffer
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_MAC_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the IP+对方MAC string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_IPMAC_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the sou IP + dst subnet_B string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_IP_subnetB_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the sou subnetB + dst IP string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_subnetB_IP_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the sou IP + dst subnet_C string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_IP_subnetC_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

    /**
     * @brief Get the sou subnetC + dst IP string from hash buffer 
     * 
     * @param buf hashbuf
     * @param len 
     * @param strbuf 字串
     * @return true 
     * @return false 
     */
    static bool         getStr_subnetC_IP_from_hashbuf(uint8_t* buf, int len, char *strbuf, int bfile=0);

public:
    /**
     * @brief 字符串转IPv4
     * 
     * @param buf 
     * @return uint32_t 
     */
    static uint32_t     trans2IP(const char* buf);

    /**
     * @brief 字符串转IPv6
     * 
     * @param buf 
     * @param ip6buf 
     * @return int 长度==16
     */
    static int          trans2IP6(const char* buf, uint8_t *ip6buf);

    /**
     * @brief 字符串转MAC址
     * 
     * @param buf 
     * @param mac 
     * @return true 
     * @return false 
     */
    static bool         trans2MAC(const char* buf, unsigned char* mac);

    /**
     * @brief 字符串转相应的IP v4 or v6
     * 
     * @param buf 
     * @param ip4 
     * @param ip6buf 
     * @return uint8_t 4--v4, 6--v6, 0--error
     */
    static uint8_t      str2IP(const char* buf, uint32_t &ip4, uint8_t *ip6buf);
public:                 //other
    /**
     * @brief 检查文件名是否pcap
     * 
     * @param filename 
     * @return true 
     * @return false 
     */
    static bool         checkPcapName(std::string filename);

    /**
     * @brief 根据pos计算hash16
     * 
     * @param pos 
     * @return uint16_t 
     */
    static uint16_t     hash16Bit(uint32_t pos);

    /**
     * @brief 根据pos计算hash8
     * 
     * @param pos 
     * @return uint8_t 
     */
    static uint8_t     hash8Bit(uint32_t pos);
private:
    static bool         B4toUS(const char* buf, uint16_t &us);
    static void         IPV6str(unsigned char* ip6, char* str, const char* cr);
};

extern "C"
{
CPacket* create_packet();
}

#endif

