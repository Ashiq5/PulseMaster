import json
from collections import defaultdict


def preprocess_live_data(data):
    if data['telemetry']['phase_1_server1'] != 'ok' or data['telemetry']['phase_2_server2'] != 'ok':
        return
    req_id_to_ip_hash = {}
    d = data['dict_of_phases']
    ans = {}
    for k in d:
        try:
            js = d[k]
            req_url = js['req_url'][7:]
            req_id = str(req_url.split(".")[0])
            req_id_to_ip_hash[req_id] = js['ip_hash']
            phase_1 = js['host-phase-1']
            server_time_1 = js['1-time']
            phase_2 = js['host-phase-2']
            if phase_2 == "err":
                errmsg[js.get("errmsg")] += 1
        except Exception as e:
            print(js)
            print('preprocess_live_data', e)


def get_leaf_files(path):
    import os
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(os.path.join(root, file))
    return list_of_files


if __name__ == "__main__":
    errmsg = defaultdict(int)
    BASE_URL = '/home/protick/node_code/dnssec_60/'
    leaf_files_unfiltered = get_leaf_files(BASE_URL)
    # print(leaf_files_unfiltered)
    
    for live_log in leaf_files_unfiltered:
        x = json.load(open(live_log))
        preprocess_live_data(x)
    # print(errmsg)
    # print(len(errmsg))

    for i in errmsg:
        if errmsg[i] > 1:
            print(i, errmsg[i])

    