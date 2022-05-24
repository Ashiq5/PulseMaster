from collections import defaultdict
import json
import numpy as np


def merge_resolver_to_asn_dict():
    d = {}
    dirs = ['1', '5', '15', '30', '60']
    for i in dirs:
        f = open('/home/protick/ocsp_dns_django/ttl_result_v2/' + i + '/final_resolver_to_asn.json')
        k = json.load(f)
        print(len(k['resolver_to_asn_own'].keys()))
        d.update(k['resolver_to_asn_own'])
        print(len(d.keys()))
    print(d['111.40.18.197'])
    print({kv[0]:kv[1] for i, kv in enumerate(d.items()) if i <= 4})
    json.dump(d, open('Outer_updates/temp/resolver-to-asn.json', 'w'), default=str, indent=4)


def merge_resolver_to_cntry_dict():
    d = {}
    dirs = ['1', '5', '15', '30', '60']
    for i in dirs:
        f = open('/home/protick/ocsp_dns_django/ttl_result_v2/' + i + '/resolver_to_org_country.json')
        k = json.load(f)
        print(len(k.keys()))
        d.update(k)
        print(len(d.keys()))
    # print(d['111.40.18.197'])
    print({kv[0]:kv[1] for i, kv in enumerate(d.items()) if i <= 4})
    json.dump(d, open('Outer_updates/temp/resolver-to-country.json', 'w'), default=str, indent=4)


def merge_resolver_to_public_local_dict():
    d = {}
    dirs = ['1', '5', '15', '30', '60']
    for i in dirs:
        f = open('/home/protick/ocsp_dns_django/ttl_result_v2/' + i + '/resolver_public_local_dict.json')
        k = json.load(f)
        print(len(k.keys()))
        d.update(k)
        print(len(d.keys()))
    # print(d['111.40.18.197'])
    print({kv[0]:kv[1] for i, kv in enumerate(d.items()) if i <= 4})
    json.dump(d, open('Outer_updates/temp/resolver_public_local_dict.json', 'w'), default=str, indent=4)


def make_resolvers_to_country_org(resolvers, fn):
    # cnt = 0
    # d = defaultdict(lambda: set())
    result = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for i in resolvers:
        if resolver_to_cntry.get(i):
            result[resolver_to_cntry.get(i)[1]][resolver_to_cntry.get(i)[0]][0] += 1
            if i not in dnssec_analysis_result:
                continue
            exit_node_cnt = sum(dnssec_analysis_result[i][j] for j in dnssec_analysis_result[i])
            result[resolver_to_cntry.get(i)[1]][resolver_to_cntry.get(i)[0]][1] += exit_node_cnt
    # print(d)
    json.dump(result, open('Outer_updates/temp/' + fn + '-resolver-to-country-org.json', 'w'), default=str, indent=4)


def find_exit_nodes(case):
    total = 0
    for i in complying_resolvers:
        # if i not in validating_resolvers:
        #         continue
        total_exit_nodes = dnssec_analysis_result[i][case]  
        # total_exit_nodes = sum(dnssec_analysis_result[i][j] for j in dnssec_analysis_result[i])
        total += total_exit_nodes
    print(total)


def make_cdf_data():
    data = []
    for i in validating_resolvers:
        if i not in dnssec_analysis_result:
                continue
        total_exit_nodes = sum(dnssec_analysis_result[i][j] for j in dnssec_analysis_result[i])
        violating_exit_nodes = dnssec_analysis_result[i]["case1.2"]
        data.append(violating_exit_nodes/total_exit_nodes)

    # sort data
    x = np.sort(data)
    print(x)

    # calculate CDF values
    y = 1. * np.arange(len(data)) / (len(data) - 1)
    print(y)

    with open('/home/ashiq/dns-ttl/data/cdf/cdf-exp-dnssec', 'w') as f:
        for i, j in zip(x, y):
            f.write(str(i) + ',' + str(j) + '\n')


def omit_some_values():
    f = open('Outer_updates/temp/cdf-ttl-openintel')
    w = open('Outer_updates/temp/cdf-ttl-openintel-short', 'w')
    line = f.readline()
    cnt = 0
    prev_x, prev_y = None, None
    while line:
        # if cnt % 100 == 0:
        x, y = int(line.strip().split(',')[0]), int(line.strip().split(',')[0])
        if prev_y and (y - prev_y) >= 0.00001:
            w.write(line)
        line = f.readline()
        cnt += 1
        prev_x, prev_y = x, y
    w.close()


def find_local_public_split():
    local, public, missing = 0, 0, 0
    print(len(pct_result))
    for i in violating_resolvers:
        if i not in resolver_to_local_public:
            missing += 1
            continue
        if resolver_to_local_public[i]:
            public += 1
        else:
            local += 1
    print(local, public, missing)

def find_raw_numbers():
    exit_node_to_req_ids = json.load(open('Outer_updates/temp/exit_node_to_req_ids'))
    req_id_to_resolver_ips = json.load(open('Outer_updates/temp/req_id_to_resolvers'))
    resolver_ips_with_DO_bit = json.load(open('Outer_updates/temp/resolver_ips_with_DO_bit'))

    total_resolver_set = set()
    for id in req_id_to_resolver_ips:
        for ip in req_id_to_resolver_ips.get(id, []):
            total_resolver_set.add(ip)
    print('total_resolvers', len(total_resolver_set), 'Total Exit Nodes', len(exit_node_to_req_ids.keys()))

    cnt_of_exit_nodes_per_resolver = defaultdict(lambda: 0)
    resolver_to_exit_nodes = defaultdict(lambda: set())
    for en in exit_node_to_req_ids:
        for id in exit_node_to_req_ids[en]:
            for ip in req_id_to_resolver_ips.get(id, []):
                cnt_of_exit_nodes_per_resolver[ip] += 1
                resolver_to_exit_nodes[ip].add(en)

    resolver_with_10_exit_nodes = set()
    exit_node_for_these_resolvers = set()
    for ip in cnt_of_exit_nodes_per_resolver:
        if cnt_of_exit_nodes_per_resolver[ip] >= 10:
            resolver_with_10_exit_nodes.add(ip)
            for en in resolver_to_exit_nodes[ip]:
                exit_node_for_these_resolvers.add(en)
    print('Resolvers with 10 exit nodes', len(resolver_with_10_exit_nodes), 'Exit node count', len(exit_node_for_these_resolvers))

    resolvers_with_do_bit_after_10_exit_nodes = set(resolver_ips_with_DO_bit).intersection(resolver_with_10_exit_nodes)
    exit_node_for_these_resolvers = set()
    for ip in resolvers_with_do_bit_after_10_exit_nodes:
        for en in resolver_to_exit_nodes[ip]:
                exit_node_for_these_resolvers.add(en)
    print('Resolvers with DO bit', len(resolvers_with_do_bit_after_10_exit_nodes), 'Exit Node count', len(exit_node_for_these_resolvers))    

    exit_node_for_these_resolvers = set()
    for ip in pct_result:
        for en in resolver_to_exit_nodes[ip]:
                exit_node_for_these_resolvers.add(en)
    print('Resolvers with pct result', len(pct_result.keys()), 'Exit node count', len(exit_node_for_these_resolvers))


def find_local_resolvers():
    resolver_to_asn = json.load(open('Outer_updates/temp/resolver-to-asn.json'))
    final_dict_elaborate = json.load(open('Outer_updates/temp/final_dict_elaborate'))
    local, missing = 0, 0
    local_ips = set()
    for i in violating_resolvers:
        asn = resolver_to_asn.get(i)
        if not asn:
            missing += 1
        data = final_dict_elaborate[i]["case1.2"]
        cnt, total = 0, len(data)
        for j in data:
            if j[8] == str(asn):
                cnt += 1
        if cnt/total >= 0.9:
            local += 1
            local_ips.add(i)
    print(local, missing)

    result = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for i in local_ips:
        if resolver_to_cntry.get(i):
            result[resolver_to_cntry.get(i)[1]][resolver_to_cntry.get(i)[0]][0] += 1
            # if i not in dnssec_analysis_result:
            #     continue
            exit_node_cnt = sum(dnssec_analysis_result[i][j] for j in dnssec_analysis_result[i])
            result[resolver_to_cntry.get(i)[1]][resolver_to_cntry.get(i)[0]][1] += exit_node_cnt
    json.dump(result, open('Outer_updates/temp/' + 'local' + '-resolver-to-country-org.json', 'w'), default=str, indent=4)





resolver_to_cntry = json.load(open('Outer_updates/temp/resolver-to-country.json'))
violating_resolvers = json.load(open('Outer_updates/temp/violating_resolvers.json'))
validating_resolvers = json.load(open('Outer_updates/temp/validating-resolvers.json'))
complying_resolvers = json.load(open('Outer_updates/temp/complying_resolvers.json'))
dnssec_analysis_result = json.load(open('Outer_updates/temp/result'))
pct_result = json.load(open('Outer_updates/temp/pct_result'))
resolver_to_local_public = json.load(open('Outer_updates/temp/resolver_public_local_dict.json'))
# print(len(resolver_to_local_public.keys()))
# print(len(dnssec_analysis_result), len(violating_resolvers), len(complying_resolvers), len(validating_resolvers))
# print(len(set(dnssec_analysis_result).intersection(set(validating_resolvers))))
# merge_resolver_to_cntry_dict()
make_resolvers_to_country_org(violating_resolvers, 'violating')
make_resolvers_to_country_org(validating_resolvers, 'validating')
# make_cdf_data()
# find_exit_nodes("case2.1")
# omit_some_values()
# merge_resolver_to_public_local_dict()
# find_local_public_split()
# find_raw_numbers()
find_local_resolvers()
