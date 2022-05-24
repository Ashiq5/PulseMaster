import datetime
from ipaddress import ip_interface
import json
import os
from collections import defaultdict
from pydoc import resolve
import re


telemetry_count = {}
final_dict = {}
final_dict_elaborate = {}
resolver_to_ips = defaultdict(lambda: set())
resolver_to_dnskey_presence = defaultdict(lambda: False)


def get_leaf_files(path):
    import os
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(os.path.join(root, file))
    return list_of_files


def initiate_per_threshold_global_sets():
    global telemetry_count
    global final_dict
    global final_dict_elaborate
    global resolver_to_ips

    telemetry_count = {}
    final_dict = {}
    final_dict_elaborate = {}
    resolver_to_ips = defaultdict(lambda: set())


def get_resolver_ips(bind_info, req_id):
    lst = bind_info.get(req_id, [])
    resolver_to_flag = defaultdict(lambda: [False, False])  # EDNS, DO
    resolver_to_timestamp = {}
    for e in lst:
        ip = e['resolver_ip']
        timestamp = datetime.datetime.timestamp(e['date'])
        if ip not in resolver_to_timestamp:
            resolver_to_timestamp[ip] = timestamp
        if 'E' in e['flags']:
            resolver_to_flag[ip][0] = True
        if 'D' in e['flags']:
            resolver_to_flag[ip][1] = True
        # if e['qtype'] == 'DNSKEY':
        #     resolver_to_flag[ip][2] = True
        #     print(e, resolver_to_flag[ip])
    return resolver_to_flag, resolver_to_timestamp 


def get_non_validating_resolver_ips(bind_info, req_id):
    resolvers = set()
    resolver_to_flag, resolver_to_timestamp = get_resolver_ips(bind_info, req_id)
    for ip in resolver_to_flag:
        if not resolver_to_flag[ip][0] or not resolver_to_flag[ip][1] or (ip in non_validating_resolvers):
            resolvers.add(ip)
    # print('non-validating resolvers', len(resolvers), resolver_to_flag[ip])
    return resolvers, resolver_to_timestamp


def get_validating_resolver_ips(bind_info, req_id):
    resolvers = set()
    resolver_to_flag, resolver_to_timestamp = get_resolver_ips(bind_info, req_id)
    for ip in resolver_to_flag:
        # if resolver_to_flag[ip][0] and resolver_to_flag[ip][1] and ip in validating_resolvers:
        if ip in validating_resolvers:
            resolvers.add(ip)
    # print('validating resolvers', len(resolvers))
    return resolvers, resolver_to_timestamp


def get_all_resolver_ips(bind_info, req_id):
    lst = bind_info.get(req_id, [])
    resolver_to_timestamp = {}
    resolvers = set()
    for e in lst:
        ip = e['resolver_ip']
        timestamp = datetime.datetime.timestamp(e['date'])
        if ip not in resolver_to_timestamp:
            resolver_to_timestamp[ip] = timestamp
        resolvers.add(ip)
    # resolver_to_flag, resolver_to_timestamp = get_resolver_ips(bind_info, req_id)
    # print('all resolvers', len(resolver_to_flag.keys()))
    return resolvers, resolver_to_timestamp


def get_ip_hit_time_tuple(req_id, apache_info_one, apache_info_two):
    phase_1_timestamp, phase_2_timestamp = "N/A", "N/A"
    try:
        phase_1_list = apache_info_one[req_id]
        phase_1_timestamp = datetime.datetime.timestamp(phase_1_list[0]['date'])
    except Exception as e:
        pass

    try:
        phase_2_list = apache_info_two[req_id]
        phase_2_timestamp = datetime.datetime.timestamp(phase_2_list[0]['date'])
    except Exception as e:
        pass
    return phase_1_timestamp, phase_2_timestamp


def does_exp_id_match(line, exp_id_list):
    prefix = ".live_dnssec_{}_".format(exp_threshold_for_this_server)
    try:
        if prefix not in line:
            return False, None
        st_index = line.find(prefix)
        sub = line[st_index + 1:]
        sub = sub.split(".")[0]
        return True, sub
    except Exception:
        return False, None


def is_event_log(log):
    for e in event_strings:
        if e in log:
            return e
    return None


def segment(lst, d1, d2):
    ans = []
    for e in lst:
        if d1 < e['date'] < d2:
            ans.append(e)
    return ans


def curate_time_segment(info, d1, d2):
    data = info["req"]
    ans = {}
    for req_id in data:
        lst = data[req_id]
        ans[req_id] = segment(lst, d1, d2)
    return ans


def save_telemetry(data):
    try:
        keys = ["phase_1_nxdomain", "phase_2_server2", "phase_2_nxdomain", "phase_1_server1"]
        nested_data = data["telemetry"]
        for key in keys:
            if key in nested_data:
                if key not in telemetry_count:
                    telemetry_count[key] = defaultdict(lambda: 0)
                telemetry_count[key][nested_data[key]] += 1
    except Exception as e:
        print('Exception in save_telemetry', e)
        pass


def preprocess_live_data(data):
    if data['telemetry']['phase_1_server1'] != 'ok' or data['telemetry']['phase_2_server2'] != 'ok':
        return
    req_id_to_ip_hash = {}
    # save_telemetry(data)
    d = data['dict_of_phases']
    ans = {}
    for k in d:
        try:
            js = d[k]
            req_url = js['req_url'][7:]
            req_id = str(req_url.split(".")[0])
            exit_node_to_req_ids[js['ip_hash']].add(req_id)
            req_id_to_ip_hash[req_id] = js['ip_hash']
            phase_1 = js['host-phase-1']
            server_time_1 = js['1-time']
            asn = js.get('asn')
            phase_2 = js.get('host-phase-2')
            if not phase_2:
                return
            elif phase_2 == "err":
                if js.get("errmsg") == "Proxy Error: No peers with requested IP available":
                    server_time_2 = None
                    phase_2 = None
                elif js.get("errmsg") == "Proxy Error: Failed to establish connection with peer":
                    server_time_2 = None
                    phase_2 = None
                elif js.get("errmsg") == "unknown":
                    server_time_2 = None
                    phase_2 = None
                elif js.get("errmsg") == "Invalid Auth":
                    server_time_2 = None
                    phase_2 = None
                elif js.get("errmsg") == "Proxy Error: socket hang up":
                    server_time_2 = None
                    phase_2 = None
                else:
                    server_time_2 = js.get('2-time')
                    phase_2 = "ServFail"  # possibly for DNSSEC failure
            else:
                server_time_2 = js['2-time']
            ans[req_id] = (phase_1, phase_2, js['asn'], server_time_1, server_time_2, asn)
        except Exception as e:
            # print(js)
            print('preprocess_live_data', e)
    return ans, req_id_to_ip_hash


def parse_bind_line_and_build_meta(line):
    l = line.strip()
    segments = l.split(" ")
    time = segments[0] + "-" + segments[1]
    resolver_ip = segments[5]
    resolver_ip = resolver_ip[: resolver_ip.rfind("#")]
    url = segments[8]
    datetime_object = datetime.datetime.strptime(time, '%d-%b-%Y-%H:%M:%S.%f')
    qt = segments[10]
    flags = segments[11]
    meta = {"date": datetime_object, "url": url, "resolver_ip": resolver_ip, "qtype": qt, "flags": flags}
    # print(meta['qtype']) if qt == 'DNSKEY' else None
    return meta


def parse_apache_line_and_build_meta(line):
    l = line.strip()
    segments = l.split(" ")
    time = segments[4]
    client_ip = segments[0]
    url = segments[-1]
    time = time[1:len(time) - 1]
    time = time.split()[0]
    datetime_object = datetime.datetime.strptime(time, '%d/%b/%Y:%H:%M:%S')

    meta = {"date": datetime_object, "url": url, "client_ip": client_ip}
    return meta


def parse_bind_apache_logs(exp_id_list, files, is_bind=True):
    ans_dict = defaultdict(lambda: dict())
    tot_files = len(files)
    index = 0

    for file in files:
        index += 1
        # if index == 2:
        #    break
        try:
            with open(file) as FileObj:
                for line in FileObj:
                    try:
                        segments = line.strip().split(" ")
                        resolver_ip = segments[5][: segments[5].rfind("#")]
                        if resolver_to_asn.get(resolver_ip) in lum_resolvers_asn:
                            continue
                        # qtype = segments[10]
                        # if qtype == 'DNSKEY':
                        #     resolver_to_dnskey_presence[resolver_ip] = True
                        if url_live not in line:
                            continue
                        is_exp_id_present, exp_id = does_exp_id_match(line, [])
                        if not is_exp_id_present:
                            continue
                        d = ans_dict[exp_id]

                        if "req" not in d:
                            d["req"] = {}
                        if is_bind:
                            if line.startswith("client"):
                                continue
                        if is_bind:
                            meta = parse_bind_line_and_build_meta(line=line)
                            if 'D' in meta['flags']:
                                resolver_ips_with_DO_bit.add(meta["resolver_ip"])
                        else:
                            meta = parse_apache_line_and_build_meta(line=line)           
                        url = meta["url"]
                        is_event = is_event_log(url)
                        if is_event:
                            if is_event not in d:
                                d[is_event] = []
                            d[is_event].append(meta)
                        else:
                            identifier = str(url.split(".")[0])
                            if identifier not in d["req"]:
                                d["req"][identifier] = list()
                            d["req"][identifier].append(meta)
                            if is_bind:
                                req_id_to_resolvers[identifier].add(meta["resolver_ip"])
                            else:
                                req_id_to_client_ips[identifier].add(meta["client_ip"])
                    except Exception as e:
                        print('parse bind apache logs ', e)
        except Exception as e:
            print('Exception in file reading', e)
            continue

        print("*** Done with parsing Bind/Apache file {}".format(file))
        print("Done with isbind {}, {}/{}".format(is_bind, index, tot_files))

    return ans_dict


def parse_logs_together(allowed_exp_ids):
    bind_dir_par = BASE_URL_BIND_APACHE + 'parent/'
    bind_files_par = [bind_dir_par + f for f in os.listdir(bind_dir_par)
                      if os.path.isfile(os.path.join(bind_dir_par, f)) and
                      '.gz' not in f]

    bind_dir_chi = BASE_URL_BIND_APACHE + 'child/'
    bind_files_chi = [bind_dir_chi + f for f in os.listdir(bind_dir_chi)
                      if os.path.isfile(os.path.join(bind_dir_chi, f)) and
                      '.gz' not in f]

    apache_logs_phase_1_dir = BASE_URL_BIND_APACHE + 'apache1/'
    apache_logs_phase_1 = [apache_logs_phase_1_dir + f for f in os.listdir(apache_logs_phase_1_dir) if
                           os.path.isfile(
                               os.path.join(apache_logs_phase_1_dir, f)) and '.gz' not in f and 'access.log' in f]

    apache_logs_phase_2_dir = BASE_URL_BIND_APACHE + 'apache2/'
    apache_logs_phase_2 = [apache_logs_phase_2_dir + f for f in os.listdir(apache_logs_phase_2_dir) if
                           os.path.isfile(
                               os.path.join(apache_logs_phase_2_dir, f)) and '.gz' not in f and 'access.log' in f]

    bind_info_global_par = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=bind_files_par, is_bind=True)
    bind_info_global_chi = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=bind_files_chi, is_bind=True)
    apache_info_one_global = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=apache_logs_phase_1,
                                                    is_bind=False)
    apache_info_two_global = parse_bind_apache_logs(exp_id_list=allowed_exp_ids, files=apache_logs_phase_2,
                                                    is_bind=False)

    return bind_info_global_par, bind_info_global_chi, apache_info_one_global, apache_info_two_global


def log_considered_resolvers(considered_resolvers, req_id, ip_hash, type_key,
                             server_time_1, server_time_2, phase1_resolver_to_timestamp,
                             phase2_resolver_to_timestamp, phase_1_apache_hit_timestamp,
                             phase_2_apache_hit_timestamp, exit_node_asn):
    for key in considered_resolvers:
        rt1, rt2 = "N/A", "N/A"
        if key in phase1_resolver_to_timestamp:
            rt1 = phase1_resolver_to_timestamp[key]
        if key in phase2_resolver_to_timestamp:
            rt2 = phase2_resolver_to_timestamp[key]
        if key not in final_dict:
            final_dict[key] = {"case1.1": 0, "case1.2": 0, "case2.1": 0, "case2.2": 0, "case3": 0}
        if key not in final_dict_elaborate:
            final_dict_elaborate[key] = {"case1.1": list(), "case1.2": list(), "case2.1": list(), "case2.2": list(), "case3": list()}
        final_dict[key][type_key] = 1 + final_dict[key][type_key]
        # req_id, ip_hash, st1, st2, rt1, rt2, wt1, wt2
        final_dict_elaborate[key][type_key].append((req_id, ip_hash, server_time_1, server_time_2,
                                                    rt1, rt2, phase_1_apache_hit_timestamp,
                                                    phase_2_apache_hit_timestamp, exit_node_asn))


def parse_logs_ttl(exp_id, bind_info, apache_info_one, apache_info_two, exp_threshold):
    lists_in_hand = [apache_info_one, apache_info_two, bind_info]
    for l in lists_in_hand:
        if 'req' in l:
            for uid in l['req']:
                l['req'][uid].sort(key=lambda x: x['date'])

    phase_1_start = datetime.datetime.utcnow()
    for uid in bind_info['req']:
        if bind_info['req'][uid][0]['date'] < phase_1_start:
            phase_1_start = bind_info['req'][uid][0]['date']
            phase_1_end = phase_1_start + datetime.timedelta(seconds=2*60)
            bind_info["phase1-start"] = phase_1_start
            bind_info["phase1-end"] = phase_1_end
    
    if "phase1-start" not in bind_info:
        print("phase1-start absent", bind_info)
    phase_1_start = bind_info["phase1-start"]
    phase_1_end = bind_info["phase1-end"]

    min_diff = 1e8
    for uid in bind_info['req']:
        for req in bind_info['req'][uid]:
            diff = (req['date'] - phase_1_start).seconds / 60
            if req['date'] > phase_1_start and diff >= 39:
                if diff < min_diff:
                    min_diff = diff
                    bind_phase_2_start = req['date']
                    bind_phase_2_end = req['date'] + datetime.timedelta(seconds=4.0*60)
                    bind_info["sleep-end"] = bind_phase_2_start
                    bind_info["phase2-end"] = bind_phase_2_end
                    break
    if 'sleep-end' not in bind_info or 'phase2-end' not in bind_info:
        return [], [], []
    
    bind_info_curated_first = curate_time_segment(bind_info, bind_info["phase1-start"], bind_info["phase1-end"])
    bind_info_curated_second = curate_time_segment(bind_info, bind_info["sleep-end"], bind_info["phase2-end"])

    apache_info_curated_first = curate_time_segment(apache_info_one, bind_info["phase1-start"], bind_info["phase1-end"])
    apache_info_curated_second = curate_time_segment(apache_info_two, bind_info["sleep-end"], bind_info["phase2-end"])

    segments = exp_id.split("_")
    exp_iteration = int(segments[-2])

    # /home/protick/node_code/dnssec_60/*/*
    live_log = open(BASE_URL + "{}/{}-out.json".format(exp_iteration, exp_id))

    # (phase_1, phase_2, js['asn'], server_time_1, server_time_2)
    x = json.load(live_log)
    if not preprocess_live_data(x):
        return [], [], []
    live_data, req_id_to_ip_hash = preprocess_live_data(x)

    # case 1 -> exitnode connects to old (cache...could be Non DNSSEC/ DNSSEC violating)
    # case 2 -> exitnode connects to new (new resolver or fetching bcs of DNSSEC invalid)
    # case 3 -> no response (could be bcs of proxy error or servfail due to Dnssec failure)
    case_1_set = set()
    case_2_set = set()
    case_3_set = set()

    for req_id in live_data:
        # case 1
        if live_data[req_id][0] == 1 and live_data[req_id][1] == 1:
            case_1_set.add(req_id)
        # case 2
        elif live_data[req_id][0] == 1 and live_data[req_id][1] == 2:
            case_2_set.add(req_id)
        elif live_data[req_id][0] == 1 and live_data[req_id][1] == "ServFail":
            case_3_set.add(req_id)

    # print("case 1", case_1_set)
    # print("case 2", case_2_set)
    # print("case 3", case_3_set)

    for req_id in case_1_set:
        phase1_apache_hit_timestamp, phase2_apache_hit_timestamp = get_ip_hit_time_tuple(req_id, apache_info_curated_first, apache_info_curated_second)
        # phase1_apache_hit_timestamp, phase2_apache_hit_timestamp = None, None

        server_time_1, server_time_2, exit_node_asn = live_data[req_id][3], live_data[req_id][4], live_data[req_id][5]

        # subcase 1.1 -> Non validating resolvers providing from cache...valid behaviour
        phase1_resolvers, phase1_resolver_to_timestamp = get_non_validating_resolver_ips(bind_info_curated_first, req_id)
        phase2_resolvers, phase2_resolver_to_timestamp = get_non_validating_resolver_ips(bind_info_curated_second, req_id)
        # print('subcase 1', phase1_resolvers, phase2_resolvers)
        subcase1_resolvers = phase1_resolvers.difference(phase2_resolvers)

        # log_considered_resolvers(considered_resolvers=subcase1_resolvers,
        #                          req_id=req_id,
        #                          ip_hash=req_id_to_ip_hash[req_id],
        #                          type_key="case1.1",
        #                          server_time_1=server_time_1,
        #                          server_time_2=server_time_2,
        #                          phase1_resolver_to_timestamp=phase1_resolver_to_timestamp,
        #                          phase2_resolver_to_timestamp=phase2_resolver_to_timestamp,
        #                          phase_1_apache_hit_timestamp=phase1_apache_hit_timestamp,
        #                          phase_2_apache_hit_timestamp=phase2_apache_hit_timestamp
        #                         )

        # subcase 1.2 -> Validating resolvers providing from cache...violation of DNSSEC
        phase1_resolvers, phase1_resolver_to_timestamp = get_validating_resolver_ips(bind_info_curated_first, req_id)
        phase2_resolvers, phase2_resolver_to_timestamp = get_validating_resolver_ips(bind_info_curated_second, req_id)
        # print('subcase 2', phase1_resolvers, phase2_resolvers)
        subcase2_resolvers = phase1_resolvers.difference(phase2_resolvers)


        log_considered_resolvers(considered_resolvers=subcase2_resolvers,
                                 req_id=req_id,
                                 ip_hash=req_id_to_ip_hash[req_id],
                                 type_key="case1.2",
                                 server_time_1=server_time_1,
                                 server_time_2=server_time_2,
                                 phase1_resolver_to_timestamp=phase1_resolver_to_timestamp,
                                 phase2_resolver_to_timestamp=phase2_resolver_to_timestamp,
                                 phase_1_apache_hit_timestamp=phase1_apache_hit_timestamp,
                                 phase_2_apache_hit_timestamp=phase2_apache_hit_timestamp,
                                 exit_node_asn=exit_node_asn
                                 )
        # print('set1', subcase1_resolvers)
        # print('set2', subcase2_resolvers)
    for req_id in case_2_set:
        phase1_apache_hit_timestamp, phase2_apache_hit_timestamp = get_ip_hit_time_tuple(req_id, apache_info_curated_first, apache_info_curated_second)
        # phase1_apache_hit_timestamp, phase2_apache_hit_timestamp = None, None
        server_time_1, server_time_2, exit_node_asn = live_data[req_id][3], live_data[req_id][4], live_data[req_id][5]

        # subcase 2.1 -> Validating resolvers fetching again bcs of cached signature expiry...valid behaviour
        phase1_resolvers, phase1_resolver_to_timestamp = get_validating_resolver_ips(bind_info_curated_first, req_id)
        phase2_resolvers, phase2_resolver_to_timestamp = get_validating_resolver_ips(bind_info_curated_second, req_id)
        # print('subcase 1', phase1_resolvers, phase2_resolvers)
        subcase1_resolvers = phase1_resolvers.intersection(phase2_resolvers)
        
        log_considered_resolvers(considered_resolvers=subcase1_resolvers,
                                 req_id=req_id,
                                 ip_hash=req_id_to_ip_hash[req_id],
                                 type_key="case2.1",
                                 server_time_1=server_time_1,
                                 server_time_2=server_time_2,
                                 phase1_resolver_to_timestamp=phase1_resolver_to_timestamp,
                                 phase2_resolver_to_timestamp=phase2_resolver_to_timestamp,
                                 phase_1_apache_hit_timestamp=phase1_apache_hit_timestamp,
                                 phase_2_apache_hit_timestamp=phase2_apache_hit_timestamp,
                                 exit_node_asn=exit_node_asn
                                 )

        # subcase 2.2 -> non-validating resolvers requesting again...explanation in our earlier experiment
        phase1_resolvers, phase1_resolver_to_timestamp = get_non_validating_resolver_ips(bind_info_curated_first, req_id)
        phase2_resolvers, phase2_resolver_to_timestamp = get_non_validating_resolver_ips(bind_info_curated_second, req_id)
        # print('subcase 1', phase1_resolvers, phase2_resolvers)
        subcase2_resolvers = phase1_resolvers.intersection(phase2_resolvers)
        # log_considered_resolvers(considered_resolvers=subcase2_resolvers,
        #                          req_id=req_id,
        #                          ip_hash=req_id_to_ip_hash[req_id],
        #                          type_key="case2.2",
        #                          server_time_1=server_time_1,
        #                          server_time_2=server_time_2,
        #                          phase1_resolver_to_timestamp=phase1_resolver_to_timestamp,
        #                          phase2_resolver_to_timestamp=phase2_resolver_to_timestamp,
        #                          phase_1_apache_hit_timestamp=phase1_apache_hit_timestamp,
        #                          phase_2_apache_hit_timestamp=phase2_apache_hit_timestamp
        #                          )

        # subcase 2.3 -> new resolvers that did not appear in the first case...ignore these

        
    for req_id in case_3_set:
        server_time_1, server_time_2, exit_node_asn = live_data[req_id][3], live_data[req_id][4], live_data[req_id][5]
        phase1_apache_hit_timestamp, phase2_apache_hit_timestamp = get_ip_hit_time_tuple(req_id, apache_info_curated_first, apache_info_curated_second)
        # phase1_apache_hit_timestamp, phase2_apache_hit_timestamp = None, None

        # subcase 3.1 -> No response found from validating resolvers in the 2nd request, bcs of DNSSEC signature violation...valid behaviour
        phase1_resolvers, phase1_resolver_to_timestamp = get_validating_resolver_ips(bind_info_curated_first, req_id)
        phase2_resolvers, phase2_resolver_to_timestamp = get_validating_resolver_ips(bind_info_curated_second, req_id)
        # print('case 3', phase1_resolvers, phase2_resolvers)
        considered_resolvers = phase1_resolvers.difference(phase2_resolvers)
        # print('set1', considered_resolvers)
        log_considered_resolvers(considered_resolvers=considered_resolvers,
                                 req_id=req_id,
                                 ip_hash=req_id_to_ip_hash[req_id],
                                 type_key="case3",
                                 server_time_1=server_time_1,
                                 server_time_2=server_time_2,
                                 phase1_resolver_to_timestamp=phase1_resolver_to_timestamp,
                                 phase2_resolver_to_timestamp=phase2_resolver_to_timestamp,
                                 phase_1_apache_hit_timestamp=phase1_apache_hit_timestamp,
                                 phase_2_apache_hit_timestamp=phase2_apache_hit_timestamp,
                                 exit_node_asn=exit_node_asn
                                 )

        # subcase 3.2 -> No response found bcs of proxy error/ exit node found error...skip these


    return case_1_set, case_2_set, case_3_set


def json_dump_set(d, fn):
    k = {}
    for i in d:
        k[i] = list(d[i])
    json.dump(k, open(fn, 'w'), default=str)


def json_dump(d, fn):
    json.dump(d, open(fn, 'w'), default=str, indent=4)


def json_load(fn):
    return json.load(open(fn))


def master_calc():
    bind_info_global_par, bind_info_global_chi, apache_info_one_global, apache_info_two_global = parse_logs_together(
        allowed_exp_ids=[])
    bind_info_global = {}

    # print(set(bind_info_global_par.keys()).intersection(set(bind_info_global_chi.keys())))
    # print(bind_info_global_chi.keys())
    # json_dump(apache_info_one_global['live_dnssec_60_30000_10'], 'Outer_updates/temp/apache1_info_global.json')
    # json_dump(apache_info_two_global['live_dnssec_60_30000_10'], 'Outer_updates/temp/apache2_info_global.json')
    # bind_info_global['live_dnssec_60_12007_16'] = {"req": {}}
    # bind_info_global['live_dnssec_60_12007_16']['req'].update(bind_info_global_par['live_dnssec_60_12007_16'].get('req', {}))
    # print(len(bind_info_global['live_dnssec_60_12007_16']['req']['cd2dc34d-482a-4569-8699-789d2d5c2bdd1652082654018']))
    # for i in bind_info_global_chi['live_dnssec_60_12007_16'].get('req', {}):
    #     bind_info_global['live_dnssec_60_12007_16']['req'][i].extend(bind_info_global_chi['live_dnssec_60_12007_16']['req'][i])
    # print(len(bind_info_global['live_dnssec_60_12007_16']['req']['cd2dc34d-482a-4569-8699-789d2d5c2bdd1652082654018']))
    # json_dump(bind_info_global['live_dnssec_60_12007_16'], 'Outer_updates/temp/bind_info_global.json')
    # json_dump(bind_info_global_par['live_dnssec_60_12007_16'], 'Outer_updates/temp/bind_info_global_par.json')
    # json_dump(bind_info_global_chi['live_dnssec_60_12007_16'], 'Outer_updates/temp/bind_info_global_chi.json')


    print("Done with parsing bind/apache logs")

    exp_to_file_list = defaultdict(lambda: list())
    for exp_threshold in exp_threshold_list:
        leaf_files_unfiltered = get_leaf_files(BASE_URL)
        leaf_files_filtered = [e.split("/")[-1] for e in leaf_files_unfiltered]
        leaf_files_filtered = [e for e in leaf_files_filtered if ".json" in e]
        exp_to_file_list[exp_threshold] = leaf_files_filtered

    for exp_threshold in [exp_threshold_for_this_server]:
        exp_id_list = []
        for element in exp_to_file_list[exp_threshold]:
            exp_id_list.append(element[: - len("-out.json")])
        initiate_per_threshold_global_sets()

        for exp_id in exp_id_list:
            try:
                bind_info_global[exp_id] = {"req": {}}
                bind_info_global[exp_id]['req'].update(bind_info_global_par[exp_id].get('req', {}))
                # print(len(bind_info_global[exp_id]['req']['cd2dc34d-482a-4569-8699-789d2d5c2bdd1652082654018']))
                for key in bind_info_global_chi[exp_id].get('req', {}):
                    if key in bind_info_global[exp_id]['req']:
                        bind_info_global[exp_id]['req'][key].extend(bind_info_global_chi[exp_id]['req'][key])
                    else:
                        bind_info_global[exp_id]['req'][key] = bind_info_global_chi[exp_id]['req'][key]
                
                # bind_info_global[exp_id].update(bind_info_global_par.get(exp_id, {}))
                # bind_info_global[exp_id].update(bind_info_global_chi.get(exp_id, {}))
                # print(exp_id, bind_info_global[exp_id])
                a, b, c = parse_logs_ttl(exp_id=exp_id,
                                        bind_info=bind_info_global[exp_id],
                                        apache_info_one=apache_info_one_global.get(exp_id, {"req": []}),
                                        apache_info_two=apache_info_two_global.get(exp_id, {"req": []}),
                                        exp_threshold=exp_threshold)
            except Exception as e:
                # pp.append('master_calc {} {}'.format(e, exp_id))
                import traceback
                traceback.print_exc()
                print('master_calc ', e, exp_id)
                continue


def parse_final_dict_elaborate():
    result = defaultdict(lambda: {})
    # final_dict = json.load(open('Outer_updates/temp/final_dict'))
    final_dict_elaborate = json.load(open('Outer_updates/temp/final_dict_elaborate'))
    for key in final_dict_elaborate:
        # print(final_dict_elaborate[key]) if key == "41.217.232.43" else None
        if key not in result:
            result[key] = {"case1.1": 0, "case2.2": 0, "case1.2": 0, "case2.1": 0, "case3": 0}
        for case in final_dict_elaborate[key]:
            ip_hash = set()
            for item in final_dict_elaborate[key][case]:
                ip_hash.add(item[1])
            result[key][case] = len(ip_hash)
    json_dump(result, 'Outer_updates/temp/result')


def parse_result():
    pct_result = defaultdict(lambda: {})
    result = json.load(open('Outer_updates/temp/result'))
    print(len(result.keys()))
    for key in result:
        total = result[key]["case1.1"] + result[key]["case1.2"] + result[key]["case2.1"] + result[key]["case3"] + result[key]["case2.2"]
        if total < 10:
            continue
        pct_result[key]["total"] = total
        if key not in pct_result:
            pct_result[key] = {"case1.1": 0, "case1.2": 0, "case2.1": 0, "case2.2": 0, "case3": 0}
        for case in result[key]:
            pct_result[key][case] = result[key][case] * 100 / total
    print(len(pct_result.keys()))
    json_dump(pct_result, 'Outer_updates/temp/pct_result')


def parse_pct_result(cache_threshold=90, other_threshold=90):
    pct_result = json.load(open('Outer_updates/temp/pct_result'))
    print(len(pct_result.keys()))
    d = defaultdict(int)
    total = 0
    violating_resolvers, complying_resolvers = set(), set()
    for key in pct_result:
        for case in pct_result[key]:
            if case == "total":
                continue
            elif case == "case1.2" or case == "case1.1":
                if pct_result[key][case] >= cache_threshold:
                    d[case] += 1
                    violating_resolvers.add(key)
            else:
                if pct_result[key][case] >= other_threshold:
                    d[case] += 1
                    complying_resolvers.add(key)
        d['total'] += 1
    print(d)
    k = {}
    for i in d:
        k[i] = d[i] / d['total']
    print(k)
    print(len(pct_result.keys()))
    json_dump(list(violating_resolvers), 'Outer_updates/temp/violating_resolvers.json')
    json_dump(list(complying_resolvers), 'Outer_updates/temp/complying_resolvers.json')
 

if __name__ == "__main__":
    BASE_URL = '/home/protick/node_code/dnssec_60/'
    BASE_URL_BIND_APACHE = "/net/data/dns-ttl/"
    url_live = 'live_dnssec_60'
    instance_id = 1  # int(os.environ['instance_id'])
    exp_threshold_list = [60]
    exp_threshold_for_this_server = exp_threshold_list[instance_id - 1]
    event_strings = ["phase1-start", "phase1-end", "sleep-end", "phase2-end"]
    req_id_to_resolvers = defaultdict(lambda: set())
    req_id_to_client_ips = defaultdict(lambda: set())
    exit_node_to_req_ids = defaultdict(lambda: set())
    resolver_ips_with_DO_bit = set()
    validating_resolvers = set(json.load(open('Outer_updates/temp/validating-resolvers.json')))
    non_validating_resolvers = set(json.load(open('Outer_updates/temp/non-validating-resolvers.json')))
    lum_resolvers_asn = [15169, 20473, 36692, 14061, 30607, 24940, 27725]
    resolver_to_asn = json.load(open('Outer_updates/temp/resolver-to-asn.json'))

    # master_calc()
    # json_dump(list(resolver_ips_with_DO_bit), 'Outer_updates/temp/resolver_ips_with_DO_bit')
    # json_dump(final_dict, 'Outer_updates/temp/final_dict')
    # json_dump(final_dict_elaborate, 'Outer_updates/temp/final_dict_elaborate')
    # json_dump_set(req_id_to_resolvers, 'Outer_updates/temp/req_id_to_resolvers')
    # json_dump(req_id_to_client_ips, 'Outer_updates/temp/req_id_to_client_ips')
    # json_dump_set(exit_node_to_req_ids, 'Outer_updates/temp/exit_node_to_req_ids')

    parse_final_dict_elaborate()
    parse_result()
    parse_pct_result()
