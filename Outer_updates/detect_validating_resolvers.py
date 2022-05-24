import datetime
import json
import os
from collections import defaultdict
import sys

instance_id = sys.argv[1]
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


def parse_bind_apache_logs(files, is_bind=True, which=1):
    global bind_info_global, apache_info_one_global, apache_info_two_global
    tot_files = len(files)
    index = 0

    for file in files:
        index += 1
        # if index == 8:
        #     break
        try:
            with open(file) as FileObj:
                for line in FileObj:
                    try:
                        # print(url_live not in line, line) if is_bind else False
                        if url_live not in line:
                            continue
                        if is_bind:
                            if line.startswith("client"):
                                continue
                        if is_bind:
                            meta = parse_bind_line_and_build_meta(line=line)
                        else:
                            meta = parse_apache_line_and_build_meta(line=line)

                        if is_bind:
                            bind_info_global[meta['resolver_ip']].append(meta)
                        else:
                            if which == 1:
                                apache_info_one_global.add(meta['url'])
                            else:
                                apache_info_two_global.add(meta['url'])
                    except Exception as e:
                        print('parse bind apache logs ', e)
        except Exception as e:
            print('Exception in file reading', e)
            continue

        print("*** Done with parsing Bind file {}".format(file))
        print("Done with isbind {}, {}/{}".format(is_bind, index, tot_files))


def parse_logs_together():
    bind_dir = BASE_URL_BIND_APACHE + 'ashiq/'
    id = int(instance_id) - 1
    low = 40
    high = 60
    print(low, high)
    bind_files = [bind_dir + f for f in os.listdir(bind_dir)
                      if os.path.isfile(os.path.join(bind_dir, f)) and
                      '.gz' not in f][low: high]
    print(bind_files)

    apache_logs_phase_1_dir = BASE_URL_BIND_APACHE + 'apache1/'
    apache_logs_phase_1 = [apache_logs_phase_1_dir + f for f in os.listdir(apache_logs_phase_1_dir) if
                           os.path.isfile(
                               os.path.join(apache_logs_phase_1_dir, f)) and '.gz' not in f and 'access.log' in f]

    apache_logs_phase_2_dir = BASE_URL_BIND_APACHE + 'apache2/'
    apache_logs_phase_2 = [apache_logs_phase_2_dir + f for f in os.listdir(apache_logs_phase_2_dir) if
                           os.path.isfile(
                               os.path.join(apache_logs_phase_2_dir, f)) and '.gz' not in f and 'access.log' in f]

    parse_bind_apache_logs(files=bind_files, is_bind=True)
    parse_bind_apache_logs(files=apache_logs_phase_1, is_bind=False, which=1)
    parse_bind_apache_logs(files=apache_logs_phase_2, is_bind=False, which=2)


def master_calc():
    parse_logs_together()
    print("Done with parsing bind/apache logs")
    print(len(bind_info_global.keys()))
    print(list(bind_info_global.keys())[0])

    result = defaultdict(lambda: dict())
    for ip in bind_info_global:
        metas = bind_info_global[ip]
        if ip == '172.253.10.1':
            print(metas)
        result[ip]['correct_apache_hit'] = 0
        result[ip]['incorrect_apache_hit'] = 0
        result[ip]['correct_req'] = 0
        result[ip]['incorrect_req'] = 0
        for meta in metas:
            if '.correct' in meta['url']:
                result[ip]['correct_req'] += 1
                if meta['url'] in apache_info_one_global:
                    result[ip]['correct_apache_hit'] += 1
            elif '.incorrect' in meta['url']:
                result[ip]['incorrect_req'] += 1
                if meta['url'] in apache_info_two_global:
                    result[ip]['incorrect_apache_hit'] += 1
    
    print(len(bind_info_global['172.253.10.1']))
    print(result['172.253.10.1']['correct_apache_hit'], result['172.253.10.1']['incorrect_apache_hit'], 
    result['172.253.10.1']['correct_req'], result['172.253.10.1']['incorrect_req'])

    json_dump(result, 'Outer_updates/temp/validating-resolver-stats')


def json_dump(d, fn):
    json.dump(d, open(fn + instance_id + '.json', 'w'), default=str) 


def json_dump_regular(d, fn):
    json.dump(d, open(fn, 'w'), default=str) 


def json_load(fn):
    return json.load(open(fn))


def merge_validating_stats():
    l = [1,2,3,4,5,6]
    d = defaultdict(lambda: {})
    for i in l:
        result = json.load(open('Outer_updates/temp/validating-resolver-stats' + str(i) + '.json'))
        for ip in result:
            if ip == '45.181.48.18':
                print(result['45.181.48.18'])
            if ip not in d:
                d[ip]['correct_apache_hit'] = 0
                d[ip]['incorrect_apache_hit'] = 0
                d[ip]['correct_req'] = 0
                d[ip]['incorrect_req'] = 0
            d[ip]['correct_apache_hit'] += result[ip]['correct_apache_hit']
            d[ip]['incorrect_apache_hit'] += result[ip]['incorrect_apache_hit']
            d[ip]['correct_req'] += result[ip]['correct_req']
            d[ip]['incorrect_req'] += result[ip]['incorrect_req']
    print(d['45.181.48.18'])
    json_dump_regular(d, 'Outer_updates/temp/validating-resolver-stats.json')

def parse_result():
    pct_result = defaultdict(lambda: {})
    result = json.load(open('Outer_updates/temp/validating-resolver-stats.json'))
    print(len(result))
    for i in result:
        try:
            x = result[i]['correct_apache_hit'] / result[i]['correct_req']
            y = result[i]['incorrect_apache_hit'] / result[i]['incorrect_req']
            pct_result[i]['correct'] = x
            pct_result[i]['incorrect'] = y
        except Exception as e:
            # print(e, result[i]['incorrect_req'], result[i]['incorrect_apache_hit'])
            continue
    json_dump_regular(pct_result, 'Outer_updates/temp/validating-resolver-pct-stats.json')


def detect_validating_resolvers():
    validating_resolvers, non_validating_resolvers = set(), set()
    result = json.load(open('Outer_updates/temp/validating-resolver-stats.json'))
    pct_result = json.load(open('Outer_updates/temp/validating-resolver-pct-stats.json'))
    for i in pct_result:
        if pct_result[i]['correct'] >= 0.6 and pct_result[i]['incorrect'] <= 0.1:
            validating_resolvers.add(i)
        else:
            non_validating_resolvers.add(i)
    print(len(result), len(pct_result), len(validating_resolvers), len(non_validating_resolvers))
    resolver_to_asn = json.load(open('Outer_updates/temp/resolver-to-asn.json'))

    val_res = list(validating_resolvers)
    lum_resolvers_asn = [15169, 20473, 36692, 14061, 30607, 24940, 27725]
    cnt, how = 0, 0
    print(len(val_res))
    for i in validating_resolvers:
        if resolver_to_asn.get(i) in lum_resolvers_asn:
            val_res.remove(i)
            continue
        cnt += 1
    print(cnt, len(val_res))
    json_dump_regular(val_res, 'Outer_updates/temp/validating-resolvers.json')
    json_dump_regular(list(non_validating_resolvers), 'Outer_updates/temp/non-validating-resolvers.json')
        

if __name__ == "__main__":
    BASE_URL_BIND_APACHE = "/net/data/dns-ttl/"
    url_live = 'live_dnssecprobing_60'

    bind_info_global = defaultdict(lambda: list())
    apache_info_one_global = set()
    apache_info_two_global = set()

    # master_calc()
    # merge_validating_stats()
    parse_result()
    detect_validating_resolvers()
