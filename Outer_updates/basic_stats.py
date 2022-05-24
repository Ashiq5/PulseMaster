import json
import datetime
from ipaddress import ip_interface
import os
from collections import defaultdict
from pydoc import resolve
import re


exit_nodes = set()
resolver_ips = set()
resolver_ips_with_DO_bit = set()
req_id_to_ip_hash = {}
req_id_to_resolvers = defaultdict(lambda: set())


def preprocess_live_data(data):
    d = data['dict_of_phases']
    for k in d:
        js = d[k]
        exit_nodes.add(js['ip_hash']) 
        req_url = js['req_url'][7:]
        req_id = str(req_url.split(".")[0])
        req_id_to_ip_hash[req_id] = js['ip_hash']


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
    return meta


def parse_bind_apache_logs(files):
    ans_dict = defaultdict(lambda: dict())
    tot_files = len(files)
    index = 0

    for file in files:
        index += 1
        # if index == 20:
        #     break
        try:
            with open(file) as FileObj:
                for line in FileObj:
                    try:
                        meta = parse_bind_line_and_build_meta(line=line)
                        if resolver_to_asn.get(meta["resolver_ip"]) in lum_resolvers_asn:
                            continue
                        if url_live not in line:
                            continue
                        is_exp_id_present, exp_id = does_exp_id_match(line, [])
                        if not is_exp_id_present:
                            continue
                        resolver_ips.add(meta["resolver_ip"])
                        if 'D' in meta['flags']:
                            resolver_ips_with_DO_bit.add(meta["resolver_ip"])           
                    except Exception as e:
                        print('parse bind apache logs ', e)
        except Exception as e:
            print('Exception in file reading', e)
            continue

        print("*** Done with parsing Bind/Apache file {}".format(file))
        print("Done with isbind {}/{}".format(index, tot_files))

    return ans_dict


def parse_logs_together():
    bind_dir_par = BASE_URL_BIND_APACHE + 'parent/'
    bind_files_par = [bind_dir_par + f for f in os.listdir(bind_dir_par)
                      if os.path.isfile(os.path.join(bind_dir_par, f)) and
                      '.gz' not in f]

    bind_dir_chi = BASE_URL_BIND_APACHE + 'child/'
    bind_files_chi = [bind_dir_chi + f for f in os.listdir(bind_dir_chi)
                      if os.path.isfile(os.path.join(bind_dir_chi, f)) and
                      '.gz' not in f]

    bind_info_global_par = parse_bind_apache_logs(files=bind_files_par)
    bind_info_global_chi = parse_bind_apache_logs(files=bind_files_chi)

    return bind_info_global_par, bind_info_global_chi


def get_leaf_files(path):
    import os
    list_of_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            list_of_files.append(os.path.join(root, file))
    return list_of_files


def parse_luminati_log(exp_id, bind_info):
    # /home/protick/node_code/dnssec_60/*/*
    segments = exp_id.split("_")
    exp_iteration = int(segments[-2])
    live_log = open(BASE_URL + "{}/{}-out.json".format(exp_iteration, exp_id))

    # (phase_1, phase_2, js['asn'], server_time_1, server_time_2)
    x = json.load(live_log)
    preprocess_live_data(x)


def master_calc():
    bind_info_global_par, bind_info_global_chi = parse_logs_together()
    bind_info_global = {}

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

        for exp_id in exp_id_list:
            try:
                bind_info_global[exp_id] = {"req": {}}
                bind_info_global[exp_id]['req'].update(bind_info_global_par[exp_id].get('req', {}))
                for key in bind_info_global_chi[exp_id].get('req', {}):
                    if key in bind_info_global[exp_id]['req']:
                        bind_info_global[exp_id]['req'][key].extend(bind_info_global_chi[exp_id]['req'][key])
                    else:
                        bind_info_global[exp_id]['req'][key] = bind_info_global_chi[exp_id]['req'][key]
                parse_luminati_log(exp_id=exp_id,
                                    bind_info=bind_info_global[exp_id],
                                   )
            except Exception as e:
                # pp.append('master_calc {} {}'.format(e, exp_id))
                import traceback
                traceback.print_exc()
                print('master_calc ', e, exp_id)
                continue

if __name__ == "__main__":
    BASE_URL = '/home/protick/node_code/dnssec_60/'
    BASE_URL_BIND_APACHE = "/net/data/dns-ttl/"
    url_live = 'live_dnssec_60'
    exp_threshold_list = [60]
    exp_threshold_for_this_server = 60
    validating_resolvers = set(json.load(open('Outer_updates/temp/validating-resolvers.json')))
    non_validating_resolvers = set(json.load(open('Outer_updates/temp/non-validating-resolvers.json')))
    lum_resolvers_asn = [15169, 20473, 36692, 14061, 30607, 24940, 27725]
    resolver_to_asn = json.load(open('Outer_updates/temp/resolver-to-asn.json'))

    master_calc()
    print(len(exit_nodes))
    print(len(resolver_ips))
    print(len(resolver_ips_with_DO_bit))
