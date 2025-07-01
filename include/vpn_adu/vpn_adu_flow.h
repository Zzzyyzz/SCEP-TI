#ifndef PL_REGRESSION_H
#define PL_REGRESSION_H

#include "_lib.h/libFlow2SE.h"
#include <vector>

struct stt_requ
{
    uint32_t len_c;
    uint32_t no_c;
    uint32_t num_c;
    double tm_c;

    uint32_t ack_begin;
    uint32_t ack_end;
    uint32_t len_s;
    uint32_t num_s;
};

struct stt_adu
{
    uint32_t len_adu;
    double tm_requ;
};

//==============================================================================
//==============================================================================
//==============================================================================

class vpn_adu_flow_creator: public IFlow2ObjectCreator
{
public:
    vpn_adu_flow_creator(packet_statistics_object_type type, std::string fn, std::string path, int thre, int min_requ, int min_resp);
    ~vpn_adu_flow_creator() {}
public:
    IFlow2Object* create_Object(uint8_t* buf, int len);
public:    
    packet_statistics_object_type getStatType() {return pso_type;}
    bool isSave() {return true;}

    std::string getName() {return str_name;}
    int get_threshold() {return pck_thre;}
    int get_min_request() {return min_request;}
    int get_min_response() {return min_response;}

    bool add_vpn_flow(std::string str_msg, std::vector<stt_adu> vct_adu){
        bool bout = false;
        FILE *fp = fopen(str_pfile.c_str(), "at");
        if(fp){
            fprintf(fp, "%s,%s,", str_name.c_str(), str_msg.c_str());
            /*
            //正序
            for(std::vector<uint32_t>::iterator iter=vct_adu.begin(); iter!=vct_adu.end(); ++iter)
                fprintf(fp, "%u,", *iter);
            */
            //逆序
            for (std::vector<stt_adu>::reverse_iterator it = vct_adu.rbegin(); it != vct_adu.rend(); it++)
                fprintf(fp, "%u,", it->len_adu);
            fprintf(fp, "\n");
            fclose(fp);
            bout = true;
        }
        fp = fopen(str_intv.c_str(), "at");
        if(fp){
            std::vector<stt_adu>::iterator iter=vct_adu.begin();
            double db_tm = iter->tm_requ;
            for(++iter; iter!=vct_adu.end(); ++iter){
                fprintf(fp, "%f\n", iter->tm_requ-db_tm);
                db_tm = iter->tm_requ;
            }
            fclose(fp);
        }
        return bout;
    }
private:
    packet_statistics_object_type pso_type;
    std::string str_name, str_path, str_pfile, str_intv;
    int pck_thre, min_request, min_response;
};

//==============================================================================
//==============================================================================
//==============================================================================

class vpn_adu_flow: public IFlow2Object
{
public:
    vpn_adu_flow(uint8_t* buf, int len, vpn_adu_flow_creator* lpFOC);
    ~vpn_adu_flow();
public:
    bool addPacket(CPacket* lppck, bool bSou);
    bool saveObject(FILE* fp, uint64_t cntP, bool bFin);
public:
    bool checkObject()
    {
        if(lenKey>0 && bufKey)
            return true;
        else
            return false;
    }

    bool isSameObject(uint8_t* buf, int len)
    {
        bool bout = false;
        if(lenKey == len)
        {
            if(memcmp(bufKey, buf, len)==0)
                bout = true;
        }
        return bout;
    }

    uint32_t getPckCnt() {return cntPck;}
    void incPckCnt() {cntPck++;}
private:
    uint32_t cntPck;
private:
    vpn_adu_flow_creator* lpCreator;
    uint8_t* bufKey;
    int lenKey;
private:
    int flow_type;
    uint32_t cnt_C, cnt_S;

    std::vector<stt_requ> vct_requ;
    stt_requ st_cur;
private:
    void init_requ();
    int calc_seq(uint32_t end_seq, uint32_t begin_seq);
};


#endif