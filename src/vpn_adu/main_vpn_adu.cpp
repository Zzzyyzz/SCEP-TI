#include <iostream>
#include <cstring>
#include <time.h>
#include <bits/stdc++.h>

#include "_lib.h/libconfig.h++"
#include "_lib.h/libPcapSE.h"
#include "winlin/winlinux.h"

#include "vpn_adu/vpn_adu_flow.h"

using namespace std;  
using namespace libconfig;

int main(int argc, char *argv[])
{
    char buf[UINT8_MAX] = "data.cfg";

    if(argc==2)
        strcpy(buf, argv[1]);

    std::cerr << "begin" << std::endl;        

    Config cfg;
    try
    {
        cfg.readFile(buf);
    }
    catch(...)
    {
        std::cerr << "I/O error while reading file." << std::endl;
        return(EXIT_FAILURE);
    }    

    try
    {
        //path
        string path = cfg.lookup("VPN_path");    
        cout << "path name: " << path << endl;
        int threshold, min_requ, min_resp;
        cfg.lookupValue("VPN_pck_thre", threshold);
        cout << "packet threshold:" << threshold << endl;
        cfg.lookupValue("VPN_min_requ", min_requ);
        cout << "min request:" << min_requ << endl;
        cfg.lookupValue("VPN_min_resp", min_resp);
        cout << "min response:" << min_resp << endl;

        if(path.length()>0)
        {
            string str_pfile = path + "0_path.vpn.csv";
            FILE *fp = fopen(str_pfile.c_str(), "wt");
            if(fp)
            {
                fprintf(fp, "file,prot,IP_a,port_a,IP_b,port_b,,");
                for(int i=1; i<=100; i++)
                    fprintf(fp, "adu%d,", i);
                fprintf(fp, "\n");
                fclose(fp);
            }
            else
                cout << "open file error: " << str_pfile << endl;

            str_pfile = path + "0_path.interval.csv";
            fp = fopen(str_pfile.c_str(), "wt");
            if(fp)
            {
                fprintf(fp, "interval\n");
                fclose(fp);
            }
            else
                cout << "open file error: " << str_pfile << endl;                

            vector<string> vctFN;
            if(iterPathPcaps(path, &vctFN))
            {
                for(vector<string>::iterator iter=vctFN.begin(); iter!=vctFN.end(); ++iter)
                {
                    string strFN = *iter;
                    cout << "pcap file:" << strFN << endl;

                    packet_statistics_object_type typeS = pso_IPPortPair;
                    IFlow2Stat* lpFS = CFlow2StatCreator::create_flow2_stat(strFN, 25, threshold, 1);
                    vpn_adu_flow_creator* lpFC = new vpn_adu_flow_creator(typeS, strFN, path, threshold, min_requ, min_resp);
                    if(lpFS && lpFC)
                    {
                        lpFS->setParameter(typeS, 1, psm_SouDstDouble, true);
                        lpFS->setCreator(lpFC);
                        if(lpFS->isChecked())
                        {
                            lpFS->iterPcap();
                        }
                        delete lpFC;
                        delete lpFS;
                    }
                    else
                        cout << "pcap file " << strFN << " open error!" << endl;
                }
            }
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return(EXIT_FAILURE);
    }

    return 0;
}