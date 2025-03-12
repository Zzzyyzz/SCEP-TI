#include <iostream>
#include <algorithm>

#include "vpn_adu/vpn_adu_flow.h"

using namespace std;

vpn_adu_flow_creator::vpn_adu_flow_creator(packet_statistics_object_type type, string fn, string path, 
                                            int thre, int min_requ, int min_resp)
{
    pso_type = type;
    str_name = fn + ".vpn.adu.csv";
    str_path = path;
    str_pfile = path + "0_path.vpn.csv";
    str_intv = path + "0_path.interval.csv";
    FILE *fp = fopen(str_name.c_str(), "wt");
    if(fp)
    {
        fprintf(fp, "prot,IP_a,port_a,IP_b,port_b,num pck,c_no,len,c_pck,time,ack_len,num s_pck\n");
        fclose(fp);
    }
    else
        cout << "open file error: " << str_name << endl;

    pck_thre = thre;
    min_request = min_requ;
    min_response = min_resp*1024;
}

IFlow2Object* vpn_adu_flow_creator::create_Object(uint8_t* buf, int len)
{
    vpn_adu_flow* lp_flow = new vpn_adu_flow(buf, len, this);
    return lp_flow;
}

//==============================================================================
//==============================================================================
//==============================================================================

vpn_adu_flow::vpn_adu_flow(uint8_t* buf, int len, vpn_adu_flow_creator* lpFOC)
{
    cntPck = 0;
    lpCreator = lpFOC;

    if(len>0)
    {
        lenKey = len;
        bufKey = (uint8_t*)calloc(lenKey, sizeof(uint8_t));
        if(bufKey)
            memcpy(bufKey, buf, len);
    }
    flow_type = 0;
    cnt_C = cnt_S = 0;
    init_requ();
}

vpn_adu_flow::~vpn_adu_flow()
{
    vct_requ.clear();
    if(bufKey)
        free(bufKey);
}

bool vpn_adu_flow::addPacket(CPacket* lppck, bool bSou)
{
    bool bout = false;

    if(lppck && flow_type>=0)
    {
        if(cntPck == 200)
        {
            if(cnt_C > 20)
            {
                flow_type = -1;
                vct_requ.clear();
            }
            else
                flow_type = 1;
        }

        if(bSou)
        {
            cnt_C ++;
            uint32_t ack_seq = lppck->getAckSeq();
            if(st_cur.no_c>0)
            {
                if(st_cur.num_s == 0)
                {
                    st_cur.len_c += lppck->getLenPayload();
                    st_cur.num_c ++;
                }
                else
                {
                    if(lppck->getLenPayload() < lpCreator->get_min_request())
                    {
                        st_cur.len_c += lppck->getLenPayload();
                        st_cur.num_c ++;
                    }
                    else
                    {
                        st_cur.ack_end = ack_seq;
                        st_cur.len_s = calc_seq(st_cur.ack_end, st_cur.ack_begin);
                        vct_requ.push_back(st_cur);
                        init_requ();

                        st_cur.tm_c = lppck->getPckOffTime();
                        st_cur.no_c = lppck->getPckNum();
                        st_cur.len_c = lppck->getLenPayload();
                        st_cur.ack_begin = ack_seq;
                        st_cur.num_c = 1;
                    }
                }
            }
            else
            {
                st_cur.tm_c = lppck->getPckOffTime();
                st_cur.no_c = lppck->getPckNum();
                st_cur.len_c = lppck->getLenPayload();
                st_cur.ack_begin = ack_seq;
                st_cur.num_c = 1;
            }
        }
        else
        {
            cnt_S ++;
            uint32_t self_seq = lppck->getSelfSeq() + lppck->getLenPayload();
            st_cur.num_s ++;
            if(st_cur.ack_end < self_seq)
                st_cur.ack_end = self_seq;
        }

        bout = true;
    }
    return bout;
}

void vpn_adu_flow::init_requ()
{
    st_cur.no_c = 0;
    st_cur.len_c = 0;
    st_cur.tm_c = 0;
    st_cur.ack_begin = 0;
    st_cur.ack_end = 0;
    st_cur.len_s = 0;
    st_cur.num_s = 0;
}

bool vpn_adu_flow::saveObject(FILE* fp, uint64_t cntP, bool bFin)
{
    bool bout = false;
    char buf_IPP[UINT8_MAX];
    vector<stt_adu> vct_adu;

    if(fp && flow_type==1)
    {
        CPacketTools::getStr_IPportpair_from_hashbuf(bufKey, lenKey, buf_IPP);
        fprintf(fp, "%s%d\n", buf_IPP, cntPck);

        if(st_cur.num_s > 0)
        {
            st_cur.len_s = calc_seq(st_cur.ack_end, st_cur.ack_begin);
            vct_requ.push_back(st_cur);
        }
        
        for(vector<stt_requ>::iterator iter=vct_requ.begin(); iter!=vct_requ.end(); ++iter)
        {
            if((*iter).len_s > lpCreator->get_min_response())
            {
                fprintf(fp, ",,,,,,%u,%u,%u,%.3f,%u,%u\n", (*iter).no_c, (*iter).len_c, (*iter).num_c, (*iter).tm_c, (*iter).len_s, (*iter).num_s);
                stt_adu st_adu;
                st_adu.len_adu = iter->len_s;
                st_adu.tm_requ = iter->tm_c;
                vct_adu.push_back(st_adu);
            }
        }

        fprintf(fp, "\n");
        string str_msg = buf_IPP;
        if(vct_adu.size() > 5)
            lpCreator->add_vpn_flow(str_msg, vct_adu);
        vct_adu.clear();
        bout = true;
    }
    return bout;
}

int vpn_adu_flow::calc_seq(uint32_t end_seq, uint32_t begin_seq)
{
    uint32_t uiout;

    if(end_seq>begin_seq)
        uiout = end_seq - begin_seq;
    else if(end_seq < begin_seq && end_seq > begin_seq - 1024*1024)
        uiout = end_seq - begin_seq;
    else if(end_seq < begin_seq - 50000000)
        uiout = (unsigned int)(0xffffffff - begin_seq + end_seq + 1);
    else
        uiout = 0;
    return uiout;
}
